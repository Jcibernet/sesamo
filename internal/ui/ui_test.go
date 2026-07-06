package ui

import (
	"strings"
	"testing"
)

func TestBrandCSS_NilWhenNothingToApply(t *testing.T) {
	cases := []struct {
		name string
		in   BrandInput
	}{
		{name: "empty input", in: BrandInput{}},
		{name: "logo only", in: BrandInput{LogoURL: "https://cdn.example.com/logo.svg"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := BrandCSS(tc.in); got != nil {
				t.Errorf("BrandCSS(%+v) = %q, want nil", tc.in, got)
			}
		})
	}
}

func TestBrandCSS_PrimaryColor(t *testing.T) {
	css := BrandCSS(BrandInput{PrimaryColor: "#e11d48"})
	if css == nil {
		t.Fatal("BrandCSS() = nil, want non-nil output")
	}
	if !strings.Contains(string(css), "--sesamo-primary: #e11d48;") {
		t.Errorf("BrandCSS output missing --sesamo-primary declaration:\n%s", css)
	}
}

func TestBrandCSS_GradientPageBG(t *testing.T) {
	gradient := "linear-gradient(135deg, #667eea 0%, #764ba2 100%)"
	css := BrandCSS(BrandInput{PageBG: gradient})
	if css == nil {
		t.Fatal("BrandCSS() = nil, want non-nil output")
	}
	s := string(css)
	if !strings.Contains(s, "--sesamo-page-bg-image: "+gradient+";") {
		t.Errorf("BrandCSS output missing --sesamo-page-bg-image declaration:\n%s", s)
	}
	if strings.Contains(s, "--sesamo-bg:") {
		t.Errorf("BrandCSS output should not emit --sesamo-bg for a gradient:\n%s", s)
	}
}

func TestBrandCSS_PlainColorPageBG(t *testing.T) {
	css := BrandCSS(BrandInput{PageBG: "#0f172a"})
	if css == nil {
		t.Fatal("BrandCSS() = nil, want non-nil output")
	}
	s := string(css)
	if !strings.Contains(s, "--sesamo-bg: #0f172a;") {
		t.Errorf("BrandCSS output missing --sesamo-bg declaration:\n%s", s)
	}
	if strings.Contains(s, "--sesamo-page-bg-image:") {
		t.Errorf("BrandCSS output should not emit --sesamo-page-bg-image for a plain color:\n%s", s)
	}
}

func TestBrandCSS_Woff2Font(t *testing.T) {
	css := BrandCSS(BrandInput{FontURL: "https://fonts.example.com/brand.woff2"})
	if css == nil {
		t.Fatal("BrandCSS() = nil, want non-nil output")
	}
	s := string(css)
	if !strings.Contains(s, `format("woff2")`) {
		t.Errorf("BrandCSS output missing format(\"woff2\"):\n%s", s)
	}
	if !strings.Contains(s, "--sesamo-font: ") {
		t.Errorf("BrandCSS output missing --sesamo-font declaration:\n%s", s)
	}
}
