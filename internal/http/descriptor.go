package http

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"

	"github.com/jcibernet/sesamo/internal/config"
)

// registerDescriptor wires the AI-first read-only discovery surface:
// GET /.well-known/sesamo (machine-readable deployment descriptor),
// GET /openapi.json and GET /llms.txt. The descriptor is derived from
// the same constants the handlers use (error codes, endpoint paths,
// config) — never hand-authored — so it cannot drift from the code.
func (s *Server) registerDescriptor() {
	// Implemented in this file; routes are added here so server.go only
	// names the seam.

	// Both documents are immutable for the process lifetime: config and
	// build version are fixed at boot. Rendering them once keeps the
	// discovery surface off the allocation path of a scraping agent.
	doc := buildDescriptor(s.cfg, s.providers.Names())
	openAPI := openAPIDocument(s.cfg.Version)

	s.mux.HandleFunc("GET /.well-known/sesamo", func(w http.ResponseWriter, r *http.Request) {
		// A short max-age lets an agent poll cheaply while still picking
		// up a redeploy that changed capabilities within minutes. Nothing
		// here is secret or per-request, so no-store would only cost
		// round trips.
		w.Header().Set("Cache-Control", "public, max-age=300")
		writeJSON(w, http.StatusOK, doc)
	})

	s.mux.HandleFunc("GET /openapi.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(openAPI)
	})

	s.mux.HandleFunc("GET /llms.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write([]byte(llmsTxt))
	})
}

// descriptorSchemaVersion is the version of the descriptor's own shape,
// bumped only on a breaking change to it. An agent that understands
// version 1 must be able to keep parsing a deployment that added fields.
const descriptorSchemaVersion = 1

// sessionRenewalHeader is the response header that announces a rolling
// renewal extended the session (set by handleIntrospect). Published so a
// gateway caching the cookie knows what to watch for.
const sessionRenewalHeader = "X-Session-Renewed"

// descriptorDoc is the public, secret-free description of one Sésamo
// deployment. Every field is either a compile-time constant of this
// package or a non-sensitive config value: no DSN, no service token, no
// admin key, no email credentials, no redirect allowlist. Adding a field
// here is a deliberate decision to publish it to unauthenticated callers.
type descriptorDoc struct {
	SchemaVersion int                    `json:"schema_version"`
	Service       descriptorService      `json:"service"`
	Project       descriptorProject      `json:"project"`
	Endpoints     descriptorEndpoints    `json:"endpoints"`
	Capabilities  descriptorCapabilities `json:"capabilities"`
	Session       descriptorSession      `json:"session"`
	Errors        []string               `json:"errors"`
}

type descriptorService struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// descriptorProject is deployment identity, not an authorization
// boundary: one deployment serves one project (docs/adr/0001), and the
// slug is never accepted from a request.
type descriptorProject struct {
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
}

// descriptorEndpoint names one route exactly as the mux registers it,
// including the {provider} / {id} wildcards, so an agent can build the
// URL without guessing. Auth states which credential the route demands.
type descriptorEndpoint struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Auth   string `json:"auth,omitempty"`
}

// Auth values for descriptorEndpoint.Auth. Absent means unauthenticated
// (or authenticated by the session cookie the flow itself issues).
const (
	authServiceToken = "bearer_service_token"
	authAdminKey     = "bearer_admin_api_key"
)

// descriptorEndpoints is the full route map, as a struct rather than a
// map so the field set is checked at compile time and the JSON key order
// is stable. The /ui/*.css routes are deliberately absent: they are
// rendering assets of the bundled login UI (and brand.css 404s when
// branding is unset), not integration surface.
type descriptorEndpoints struct {
	Descriptor          descriptorEndpoint `json:"descriptor"`
	Login               descriptorEndpoint `json:"login"`
	LoginSubmit         descriptorEndpoint `json:"login_submit"`
	Signup              descriptorEndpoint `json:"signup"`
	Logout              descriptorEndpoint `json:"logout"`
	OAuthStart          descriptorEndpoint `json:"oauth_start"`
	OAuthCallback       descriptorEndpoint `json:"oauth_callback"`
	ResetPage           descriptorEndpoint `json:"reset_page"`
	Reset               descriptorEndpoint `json:"reset"`
	ResetConfirmPage    descriptorEndpoint `json:"reset_confirm_page"`
	ResetConfirm        descriptorEndpoint `json:"reset_confirm"`
	Verify              descriptorEndpoint `json:"verify"`
	MagicLink           descriptorEndpoint `json:"magiclink"`
	MagicLinkConfirm    descriptorEndpoint `json:"magiclink_confirm"`
	Introspect          descriptorEndpoint `json:"introspect"`
	RevokeSession       descriptorEndpoint `json:"revoke_session"`
	AdminUser           descriptorEndpoint `json:"admin_user"`
	AdminRevokeSessions descriptorEndpoint `json:"admin_revoke_sessions"`
	AdminDisable        descriptorEndpoint `json:"admin_disable"`
	Healthz             descriptorEndpoint `json:"healthz"`
	Readyz              descriptorEndpoint `json:"readyz"`
	Metrics             descriptorEndpoint `json:"metrics"`
	OpenAPI             descriptorEndpoint `json:"openapi"`
	LLMs                descriptorEndpoint `json:"llms"`
}

type descriptorCapabilities struct {
	Password  bool `json:"password"`
	MagicLink bool `json:"magic_link"`
	// OAuthProviders lists only the providers this deployment actually
	// registered — a half-configured provider never boots (buildProviders),
	// so presence here means the flow works.
	OAuthProviders []string `json:"oauth_providers"`
	Signup         string   `json:"signup"`
}

// descriptorSession publishes the session contract a consuming backend
// or gateway has to honor. Lifetimes are seconds because an agent should
// not have to parse Go duration strings.
type descriptorSession struct {
	CookieName              string `json:"cookie_name"`
	Secure                  bool   `json:"secure"`
	SameSite                string `json:"same_site"`
	LifetimeSeconds         int64  `json:"lifetime_seconds"`
	AbsoluteLifetimeSeconds int64  `json:"absolute_lifetime_seconds"`
	RenewalHeader           string `json:"renewal_header"`
}

// buildDescriptor assembles the descriptor from config and this
// package's constants. It is pure — no pool, no request, no clock — so
// the HTTP handler and `sesamo describe` share one implementation and
// the CLI needs no database.
func buildDescriptor(cfg *config.Config, oauthProviders []string) descriptorDoc {
	// Registry.Names() iterates a map, so its order is random per call.
	// The descriptor is a cached, byte-compared document: sort to make it
	// deterministic. Non-nil so the JSON is [] instead of null.
	providers := slices.Clone(oauthProviders)
	if providers == nil {
		providers = []string{}
	}
	slices.Sort(providers)

	version := cfg.Version
	if version == "" {
		version = "dev"
	}

	return descriptorDoc{
		SchemaVersion: descriptorSchemaVersion,
		Service:       descriptorService{Name: "sesamo", Version: version},
		Project: descriptorProject{
			Slug:        cfg.ProjectSlug,
			DisplayName: cfg.ProjectDisplayName,
		},
		Endpoints: descriptorEndpoints{
			Descriptor:          descriptorEndpoint{Method: "GET", Path: "/.well-known/sesamo"},
			Login:               descriptorEndpoint{Method: "GET", Path: "/login"},
			LoginSubmit:         descriptorEndpoint{Method: "POST", Path: "/login"},
			Signup:              descriptorEndpoint{Method: "POST", Path: "/signup"},
			Logout:              descriptorEndpoint{Method: "POST", Path: "/logout"},
			OAuthStart:          descriptorEndpoint{Method: "GET", Path: "/auth/{provider}"},
			OAuthCallback:       descriptorEndpoint{Method: "GET", Path: "/auth/{provider}/callback"},
			ResetPage:           descriptorEndpoint{Method: "GET", Path: "/reset"},
			Reset:               descriptorEndpoint{Method: "POST", Path: "/reset"},
			ResetConfirmPage:    descriptorEndpoint{Method: "GET", Path: "/reset/confirm"},
			ResetConfirm:        descriptorEndpoint{Method: "POST", Path: "/reset/confirm"},
			Verify:              descriptorEndpoint{Method: "GET", Path: "/verify"},
			MagicLink:           descriptorEndpoint{Method: "POST", Path: "/magiclink"},
			MagicLinkConfirm:    descriptorEndpoint{Method: "GET", Path: "/magiclink/confirm"},
			Introspect:          descriptorEndpoint{Method: "POST", Path: "/v1/introspect", Auth: authServiceToken},
			RevokeSession:       descriptorEndpoint{Method: "POST", Path: "/v1/sessions/revoke", Auth: authServiceToken},
			AdminUser:           descriptorEndpoint{Method: "GET", Path: "/v1/admin/users/{id}", Auth: authAdminKey},
			AdminRevokeSessions: descriptorEndpoint{Method: "POST", Path: "/v1/admin/users/{id}/revoke-sessions", Auth: authAdminKey},
			AdminDisable:        descriptorEndpoint{Method: "POST", Path: "/v1/admin/users/{id}/disable", Auth: authAdminKey},
			Healthz:             descriptorEndpoint{Method: "GET", Path: "/healthz"},
			Readyz:              descriptorEndpoint{Method: "GET", Path: "/readyz"},
			Metrics:             descriptorEndpoint{Method: "GET", Path: "/metrics"},
			OpenAPI:             descriptorEndpoint{Method: "GET", Path: "/openapi.json"},
			LLMs:                descriptorEndpoint{Method: "GET", Path: "/llms.txt"},
		},
		Capabilities: descriptorCapabilities{
			Password:       true,
			MagicLink:      true,
			OAuthProviders: providers,
			Signup:         cfg.Signup,
		},
		Session: descriptorSession{
			CookieName:              cfg.CookieName,
			Secure:                  cfg.CookieSecure,
			SameSite:                "Lax",
			LifetimeSeconds:         int64(cfg.SessionLifetime.Seconds()),
			AbsoluteLifetimeSeconds: int64(cfg.SessionMaxLifetime.Seconds()),
			RenewalHeader:           sessionRenewalHeader,
		},
		Errors: stableErrorCodes,
	}
}

// DescribeJSON renders the deployment descriptor without touching the
// database, for `sesamo describe`. It builds the OAuth registry the same
// way NewServer does, so a provider the operator misconfigured fails
// here too instead of being quietly omitted from the description.
func DescribeJSON(cfg *config.Config) ([]byte, error) {
	providers, err := buildProviders(cfg)
	if err != nil {
		return nil, err
	}
	// Indented: this output is read by humans and agents on a terminal,
	// unlike the endpoint's compact body. Semantically identical.
	return json.MarshalIndent(buildDescriptor(cfg, providers.Names()), "", "  ")
}

// openAPIVersionPlaceholder is the literal the template carries where
// info.version belongs. It is substituted at boot instead of being
// formatted in, so the spec below stays a plain readable JSON document
// that a test can parse verbatim.
const openAPIVersionPlaceholder = `"0.0.0-placeholder"`

// openAPIDocument returns the OpenAPI 3.1 spec with info.version set to
// the running build version.
func openAPIDocument(version string) []byte {
	if version == "" {
		version = "dev"
	}
	// Marshal rather than concatenate quotes: a version string from
	// -ldflags is operator input and must not be able to break the JSON.
	quoted, err := json.Marshal(version)
	if err != nil {
		quoted = []byte(`"dev"`)
	}
	return []byte(strings.Replace(openAPISpec, openAPIVersionPlaceholder, string(quoted), 1))
}

// openAPISpec is the HTTP contract of the public and S2S surface. It is
// kept as a literal document (not marshaled structs) because it is read
// far more often than it is edited, and a diff of it should be legible.
// Response bodies reference the two shapes callers actually parse:
// apiError (errors.go) and introspectResponse (service.go).
const openAPISpec = `{
  "openapi": "3.1.0",
  "info": {
    "title": "Sésamo",
    "version": "0.0.0-placeholder",
    "summary": "Servidor de autenticación con sesiones opacas en Postgres.",
    "description": "Superficie HTTP de un deployment de Sésamo. Un deployment sirve un solo project (single-tenant). Descubrimiento en tiempo de ejecución: GET /.well-known/sesamo."
  },
  "servers": [{ "url": "/", "description": "Este deployment (rutas relativas)." }],
  "tags": [
    { "name": "enduser", "description": "Flujos de usuario final (navegador o cliente headless)." },
    { "name": "service", "description": "Server-to-server; requiere SESAMO_SERVICE_TOKEN." },
    { "name": "admin", "description": "Administración; requiere SESAMO_ADMIN_API_KEY." },
    { "name": "ops", "description": "Salud, métricas y descubrimiento." }
  ],
  "paths": {
    "/login": {
      "get": {
        "tags": ["enduser"],
        "summary": "Métodos de login disponibles y token CSRF.",
        "description": "HTML por defecto. Con Accept: application/json o ?mode=json devuelve providers, methods y csrf_token; el token acompaña a los POST de esta sección.",
        "parameters": [
          { "name": "mode", "in": "query", "required": false, "schema": { "type": "string", "enum": ["json"] } }
        ],
        "responses": {
          "200": {
            "description": "Página de login o descripción de métodos.",
            "content": {
              "application/json": { "schema": { "$ref": "#/components/schemas/LoginOptions" } },
              "text/html": { "schema": { "type": "string" } }
            }
          }
        }
      },
      "post": {
        "tags": ["enduser"],
        "summary": "Login con email y contraseña.",
        "requestBody": {
          "required": true,
          "content": {
            "application/x-www-form-urlencoded": {
              "schema": {
                "type": "object",
                "required": ["email", "password"],
                "properties": {
                  "email": { "type": "string", "format": "email" },
                  "password": { "type": "string" },
                  "csrf_token": { "type": "string", "description": "Alternativa al header X-CSRF-Token." }
                }
              }
            }
          }
        },
        "responses": {
          "200": { "$ref": "#/components/responses/SessionEstablished" },
          "303": { "description": "Redirección al destino post-login (modo navegador)." },
          "400": { "$ref": "#/components/responses/Error" },
          "401": { "$ref": "#/components/responses/Error" },
          "403": { "$ref": "#/components/responses/Error" },
          "429": { "$ref": "#/components/responses/Error" }
        }
      }
    },
    "/signup": {
      "post": {
        "tags": ["enduser"],
        "summary": "Registro de una cuenta nueva.",
        "description": "Deshabilitado cuando SESAMO_SIGNUP=disabled; consultar capabilities.signup en el descriptor.",
        "requestBody": {
          "required": true,
          "content": {
            "application/x-www-form-urlencoded": {
              "schema": {
                "type": "object",
                "required": ["email", "password"],
                "properties": {
                  "email": { "type": "string", "format": "email" },
                  "password": { "type": "string" },
                  "name": { "type": "string" },
                  "csrf_token": { "type": "string" }
                }
              }
            }
          }
        },
        "responses": {
          "200": { "$ref": "#/components/responses/SessionEstablished" },
          "303": { "description": "Redirección post-registro (modo navegador)." },
          "400": { "$ref": "#/components/responses/Error" },
          "403": { "$ref": "#/components/responses/Error" },
          "429": { "$ref": "#/components/responses/Error" }
        }
      }
    },
    "/logout": {
      "post": {
        "tags": ["enduser"],
        "summary": "Cierra la sesión actual.",
        "description": "Solo POST y con par CSRF: un GET de logout se dispara desde cualquier imagen remota.",
        "responses": {
          "200": { "$ref": "#/components/responses/Status" },
          "303": { "description": "Redirección post-logout (modo navegador)." },
          "403": { "$ref": "#/components/responses/Error" }
        }
      }
    },
    "/auth/{provider}": {
      "get": {
        "tags": ["enduser"],
        "summary": "Inicia el flujo OAuth de un provider habilitado.",
        "parameters": [{ "$ref": "#/components/parameters/Provider" }],
        "responses": {
          "303": { "description": "Redirección al authorization endpoint del provider." },
          "404": { "$ref": "#/components/responses/Error" }
        }
      }
    },
    "/auth/{provider}/callback": {
      "get": {
        "tags": ["enduser"],
        "summary": "Callback OAuth: valida state y PKCE, y establece la sesión.",
        "parameters": [
          { "$ref": "#/components/parameters/Provider" },
          { "name": "code", "in": "query", "required": false, "schema": { "type": "string" } },
          { "name": "state", "in": "query", "required": false, "schema": { "type": "string" } }
        ],
        "responses": {
          "303": { "description": "Redirección al destino post-login." },
          "400": { "$ref": "#/components/responses/Error" },
          "403": { "$ref": "#/components/responses/Error" },
          "502": { "$ref": "#/components/responses/Error" }
        }
      }
    },
    "/reset": {
      "get": {
        "tags": ["enduser"],
        "summary": "Formulario de pedido de reset.",
        "responses": { "200": { "description": "Página de pedido de reset." } }
      },
      "post": {
        "tags": ["enduser"],
        "summary": "Pide un email de reset de contraseña.",
        "description": "Respuesta idéntica exista o no la cuenta: no es un oráculo de enumeración.",
        "requestBody": {
          "required": true,
          "content": {
            "application/x-www-form-urlencoded": {
              "schema": {
                "type": "object",
                "required": ["email"],
                "properties": {
                  "email": { "type": "string", "format": "email" },
                  "csrf_token": { "type": "string" }
                }
              }
            }
          }
        },
        "responses": {
          "200": { "$ref": "#/components/responses/Status" },
          "303": { "description": "Redirección con acuse genérico." },
          "403": { "$ref": "#/components/responses/Error" },
          "429": { "$ref": "#/components/responses/Error" }
        }
      }
    },
    "/reset/confirm": {
      "get": {
        "tags": ["enduser"],
        "summary": "Formulario de nueva contraseña para un token de reset.",
        "parameters": [{ "$ref": "#/components/parameters/Token" }],
        "responses": { "200": { "description": "Página de nueva contraseña." } }
      },
      "post": {
        "tags": ["enduser"],
        "summary": "Consume el token de reset y fija la contraseña nueva.",
        "requestBody": {
          "required": true,
          "content": {
            "application/x-www-form-urlencoded": {
              "schema": {
                "type": "object",
                "required": ["token", "password"],
                "properties": {
                  "token": { "type": "string" },
                  "password": { "type": "string" },
                  "csrf_token": { "type": "string" }
                }
              }
            }
          }
        },
        "responses": {
          "200": { "$ref": "#/components/responses/Status" },
          "303": { "description": "Redirección al login." },
          "400": { "$ref": "#/components/responses/Error" },
          "403": { "$ref": "#/components/responses/Error" }
        }
      }
    },
    "/verify": {
      "get": {
        "tags": ["enduser"],
        "summary": "Verifica una dirección de email con el token enviado.",
        "parameters": [{ "$ref": "#/components/parameters/Token" }],
        "responses": {
          "200": { "$ref": "#/components/responses/Status" },
          "303": { "description": "Redirección con el resultado." },
          "400": { "$ref": "#/components/responses/Error" }
        }
      }
    },
    "/magiclink": {
      "post": {
        "tags": ["enduser"],
        "summary": "Pide un link de acceso sin contraseña.",
        "description": "Respuesta idéntica exista o no la cuenta.",
        "requestBody": {
          "required": true,
          "content": {
            "application/x-www-form-urlencoded": {
              "schema": {
                "type": "object",
                "required": ["email"],
                "properties": {
                  "email": { "type": "string", "format": "email" },
                  "csrf_token": { "type": "string" }
                }
              }
            }
          }
        },
        "responses": {
          "200": { "$ref": "#/components/responses/Status" },
          "303": { "description": "Redirección con acuse genérico." },
          "403": { "$ref": "#/components/responses/Error" },
          "429": { "$ref": "#/components/responses/Error" }
        }
      }
    },
    "/magiclink/confirm": {
      "get": {
        "tags": ["enduser"],
        "summary": "Consume el token de magic link y establece la sesión.",
        "parameters": [{ "$ref": "#/components/parameters/Token" }],
        "responses": {
          "200": { "$ref": "#/components/responses/SessionEstablished" },
          "303": { "description": "Redirección al destino post-login." },
          "400": { "$ref": "#/components/responses/Error" }
        }
      }
    },
    "/v1/introspect": {
      "post": {
        "tags": ["service"],
        "summary": "Resuelve un token de sesión opaco a una identidad.",
        "description": "Camino caliente de integración. El token viaja en el campo token o en la cookie de sesión reenviada por el gateway. Un token inválido o vencido no es un error: responde 200 con active=false.",
        "security": [{ "serviceToken": [] }],
        "requestBody": {
          "required": false,
          "content": {
            "application/x-www-form-urlencoded": {
              "schema": {
                "type": "object",
                "properties": { "token": { "type": "string", "description": "Valor crudo de la cookie de sesión." } }
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": "Resultado de la introspección.",
            "headers": {
              "X-Session-Renewed": {
                "description": "Presente con valor 1 cuando la renovación rolling extendió la sesión.",
                "schema": { "type": "string" }
              }
            },
            "content": {
              "application/json": { "schema": { "$ref": "#/components/schemas/IntrospectResponse" } }
            }
          },
          "401": { "$ref": "#/components/responses/Error" },
          "500": { "$ref": "#/components/responses/Error" },
          "503": { "$ref": "#/components/responses/Error" }
        }
      }
    },
    "/v1/sessions/revoke": {
      "post": {
        "tags": ["service"],
        "summary": "Revoca una sesión por token.",
        "security": [{ "serviceToken": [] }],
        "requestBody": {
          "required": true,
          "content": {
            "application/x-www-form-urlencoded": {
              "schema": {
                "type": "object",
                "required": ["token"],
                "properties": { "token": { "type": "string" } }
              }
            }
          }
        },
        "responses": {
          "200": { "$ref": "#/components/responses/Status" },
          "400": { "$ref": "#/components/responses/Error" },
          "401": { "$ref": "#/components/responses/Error" },
          "500": { "$ref": "#/components/responses/Error" }
        }
      }
    },
    "/v1/admin/users/{id}": {
      "get": {
        "tags": ["admin"],
        "summary": "Devuelve un usuario por id.",
        "security": [{ "adminKey": [] }],
        "parameters": [{ "$ref": "#/components/parameters/UserID" }],
        "responses": {
          "200": {
            "description": "Usuario.",
            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/User" } } }
          },
          "401": { "$ref": "#/components/responses/Error" },
          "404": { "$ref": "#/components/responses/Error" },
          "503": { "$ref": "#/components/responses/Error" }
        }
      }
    },
    "/v1/admin/users/{id}/revoke-sessions": {
      "post": {
        "tags": ["admin"],
        "summary": "Revoca todas las sesiones de un usuario.",
        "security": [{ "adminKey": [] }],
        "parameters": [{ "$ref": "#/components/parameters/UserID" }],
        "responses": {
          "200": { "$ref": "#/components/responses/Status" },
          "401": { "$ref": "#/components/responses/Error" },
          "500": { "$ref": "#/components/responses/Error" }
        }
      }
    },
    "/v1/admin/users/{id}/disable": {
      "post": {
        "tags": ["admin"],
        "summary": "Habilita o deshabilita una cuenta.",
        "description": "El campo disabled lleva el estado deseado, así que el mismo endpoint deshabilita y revierte. Deshabilitar revoca además todas las sesiones vivas.",
        "security": [{ "adminKey": [] }],
        "parameters": [{ "$ref": "#/components/parameters/UserID" }],
        "requestBody": {
          "required": true,
          "content": {
            "application/x-www-form-urlencoded": {
              "schema": {
                "type": "object",
                "required": ["disabled"],
                "properties": { "disabled": { "type": "boolean" } }
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": "Estado aplicado.",
            "content": {
              "application/json": {
                "schema": {
                  "type": "object",
                  "properties": {
                    "status": { "type": "string" },
                    "user_id": { "type": "string" },
                    "disabled": { "type": "boolean" }
                  }
                }
              }
            }
          },
          "400": { "$ref": "#/components/responses/Error" },
          "401": { "$ref": "#/components/responses/Error" },
          "404": { "$ref": "#/components/responses/Error" },
          "500": { "$ref": "#/components/responses/Error" }
        }
      }
    },
    "/healthz": {
      "get": {
        "tags": ["ops"],
        "summary": "Liveness: el proceso responde.",
        "responses": { "200": { "description": "ok", "content": { "text/plain": { "schema": { "type": "string" } } } } }
      }
    },
    "/readyz": {
      "get": {
        "tags": ["ops"],
        "summary": "Readiness: la base responde.",
        "responses": {
          "200": { "description": "ready", "content": { "text/plain": { "schema": { "type": "string" } } } },
          "503": { "description": "db unavailable", "content": { "text/plain": { "schema": { "type": "string" } } } }
        }
      }
    },
    "/metrics": {
      "get": {
        "tags": ["ops"],
        "summary": "Métricas en formato de exposición Prometheus.",
        "responses": { "200": { "description": "Métricas.", "content": { "text/plain": { "schema": { "type": "string" } } } } }
      }
    },
    "/.well-known/sesamo": {
      "get": {
        "tags": ["ops"],
        "summary": "Descriptor del deployment, legible por máquinas.",
        "responses": {
          "200": {
            "description": "Descriptor.",
            "content": { "application/json": { "schema": { "type": "object" } } }
          }
        }
      }
    },
    "/openapi.json": {
      "get": {
        "tags": ["ops"],
        "summary": "Este documento.",
        "responses": { "200": { "description": "Especificación OpenAPI.", "content": { "application/json": { "schema": { "type": "object" } } } } }
      }
    },
    "/llms.txt": {
      "get": {
        "tags": ["ops"],
        "summary": "Guía corta de integración para agentes.",
        "responses": { "200": { "description": "Texto plano.", "content": { "text/plain": { "schema": { "type": "string" } } } } }
      }
    }
  },
  "components": {
    "securitySchemes": {
      "serviceToken": {
        "type": "http",
        "scheme": "bearer",
        "description": "SESAMO_SERVICE_TOKEN. Habilita introspección y revocación, nunca administración."
      },
      "adminKey": {
        "type": "http",
        "scheme": "bearer",
        "description": "SESAMO_ADMIN_API_KEY. Debe diferir del service token."
      }
    },
    "parameters": {
      "Provider": {
        "name": "provider",
        "in": "path",
        "required": true,
        "description": "Nombre del provider OAuth; los habilitados están en capabilities.oauth_providers.",
        "schema": { "type": "string", "enum": ["google", "github", "apple"] }
      },
      "Token": {
        "name": "token",
        "in": "query",
        "required": true,
        "description": "Token de un solo uso enviado por email.",
        "schema": { "type": "string" }
      },
      "UserID": {
        "name": "id",
        "in": "path",
        "required": true,
        "schema": { "type": "string", "format": "uuid" }
      }
    },
    "responses": {
      "Error": {
        "description": "Error con código estable.",
        "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Error" } } }
      },
      "Status": {
        "description": "Acuse de la operación.",
        "content": {
          "application/json": {
            "schema": { "type": "object", "properties": { "status": { "type": "string" } } }
          }
        }
      },
      "SessionEstablished": {
        "description": "Sesión creada; la cookie de sesión viaja en Set-Cookie (HttpOnly, SameSite=Lax).",
        "content": {
          "application/json": { "schema": { "type": "object", "properties": { "status": { "type": "string" } } } }
        }
      }
    },
    "schemas": {
      "Error": {
        "type": "object",
        "required": ["error"],
        "description": "Forma única de error de toda respuesta JSON. El código es estable y legible por máquina; el mensaje es humano y deliberadamente genérico.",
        "properties": {
          "error": {
            "type": "object",
            "required": ["code", "message"],
            "properties": {
              "code": {
                "type": "string",
                "enum": [
                  "invalid_credentials",
                  "invalid_request",
                  "rate_limited",
                  "unauthorized",
                  "forbidden",
                  "not_found",
                  "internal_error",
                  "state_mismatch",
                  "oauth_failed",
                  "csrf_failed"
                ]
              },
              "message": { "type": "string" }
            }
          }
        }
      },
      "IntrospectResponse": {
        "type": "object",
        "required": ["active"],
        "description": "Con la forma de RFC 7662: active es el único campo que todo caller debe chequear. El resto se omite cuando active es false.",
        "properties": {
          "active": { "type": "boolean" },
          "user_id": { "type": "string", "format": "uuid" },
          "email": { "type": "string", "format": "email" },
          "email_verified": { "type": "boolean" },
          "name": { "type": ["string", "null"] },
          "expires_at": { "type": "integer", "format": "int64", "description": "Epoch en segundos." },
          "metadata": { "type": "object", "additionalProperties": true }
        }
      },
      "LoginOptions": {
        "type": "object",
        "properties": {
          "providers": { "type": "array", "items": { "type": "string" } },
          "methods": { "type": "array", "items": { "type": "string" } },
          "csrf_token": { "type": "string", "description": "Mandarlo en el campo csrf_token o en el header X-CSRF-Token." },
          "branding": { "type": "object", "additionalProperties": true }
        }
      },
      "User": {
        "type": "object",
        "properties": {
          "id": { "type": "string", "format": "uuid" },
          "email": { "type": "string", "format": "email" },
          "email_verified": { "type": "boolean" },
          "name": { "type": ["string", "null"] },
          "disabled": { "type": "boolean" },
          "created_at": { "type": "string", "format": "date-time" },
          "metadata": { "type": "object", "additionalProperties": true }
        }
      }
    }
  }
}
`

// llmsTxt is the integration briefing for an agent that just found this
// deployment. It stays short and points at the machine-readable
// documents instead of restating them, and uses relative paths only: the
// public origin is whatever the agent already dialed.
const llmsTxt = `# Sésamo

Servidor de autenticación con sesiones opacas en Postgres. Un deployment
sirve un solo project (single-tenant): ninguna request lleva tenant.

## Descubrimiento

- GET /.well-known/sesamo  descriptor JSON y fuente de verdad: versión,
  project, endpoints, capacidades, sesión y catálogo de errores.
- GET /openapi.json        contrato HTTP completo (OpenAPI 3.1).

## Validar una sesión

La sesión vive en una cookie opaca (session.cookie_name del descriptor,
por defecto "sid"). No la parsees: no es un JWT y no lleva claims.

    POST /v1/introspect
    Authorization: Bearer $SESAMO_SERVICE_TOKEN
    Content-Type: application/x-www-form-urlencoded

    token=<valor crudo de la cookie de sesión>

Devuelve 200 con {"active":true,"user_id","email",...} o
{"active":false}. Un token vencido, revocado o inexistente NO es un error
HTTP: es active=false, así que chequeá active antes que cualquier otro
campo. El header X-Session-Renewed: 1 avisa que la sesión se extendió y
un gateway que cachea la cookie debería refrescarla. Para cerrar sesión
desde el backend: POST /v1/sessions/revoke, mismo Bearer, mismo token.

## Login headless y contrato CSRF

Todo POST que muta estado (login, signup, logout, reset, magiclink) exige
un par CSRF de doble envío. La cookie es HttpOnly, así que el token se
pide explícitamente:

1. GET /login con Accept: application/json (o ?mode=json) devuelve
   {"providers","methods","csrf_token"} y setea la cookie CSRF.
2. Reenviá esa cookie y mandá el token en el header X-CSRF-Token (o en el
   campo de formulario csrf_token).

Sin el par la respuesta es 403 con código csrf_failed. Para OAuth usá
/auth/{provider} y su callback; los providers habilitados están en
capabilities.oauth_providers.

## Errores

Forma única: {"error":{"code":"...","message":"..."}}. El code es estable
y es lo que hay que programar; el message es humano y puede cambiar. Los
diez: invalid_credentials, invalid_request, rate_limited, unauthorized,
forbidden, not_found, internal_error, state_mismatch, oauth_failed,
csrf_failed; el descriptor los publica en su campo "errors". Reset y
magiclink responden igual exista o no la cuenta: no sirven para averiguar
si un email está registrado.

## Configuración

Solo variables de entorno (SESAMO_*), documentadas en .env.example del
repositorio. No hay archivo ni API de configuración: nada de lo que este
servidor expone permite cambiarla. Para ver el descriptor sin levantar el
servidor: sesamo describe.
`
