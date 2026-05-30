package apps

import "testing"

func TestPermit(t *testing.T) {
	a := &App{
		AllowedSubs:   []string{"break-glass-user"},
		DefaultGroups: []string{"users"},
		Rules: []Rule{
			{PathPrefix: "/admin", AllowedGroups: []string{"admins"}},
			{PathPrefix: "/", AllowedGroups: []string{"users"}},
		},
	}
	cases := []struct {
		name    string
		path    string
		subject string
		groups  []string
		want    bool
	}{
		{"admin path with admins group", "/admin/dashboard", "u1", []string{"admins"}, true},
		{"admin path without admins group", "/admin/dashboard", "u1", []string{"users"}, false},
		{"root path with users group", "/foo", "u1", []string{"users"}, true},
		{"root path without any matching group", "/foo", "u1", []string{"random"}, false},
		{"break-glass sub passes on /admin without group", "/admin", "break-glass-user", nil, true},
		{"first-match wins: /admin not /", "/admin", "u1", []string{"users"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := a.Permit(tc.path, tc.subject, tc.groups)
			if got != tc.want {
				t.Fatalf("Permit(%q,%q,%v) = %v, want %v", tc.path, tc.subject, tc.groups, got, tc.want)
			}
		})
	}
}

func TestPermitNoRulesNoDefault(t *testing.T) {
	// With no rules and no default, any authenticated user passes.
	a := &App{}
	if !a.Permit("/anything", "u1", nil) {
		t.Fatal("expected permit with empty policy")
	}
}

func TestPermitDefaultOnly(t *testing.T) {
	a := &App{DefaultGroups: []string{"users"}}
	if a.Permit("/x", "u", []string{"random"}) {
		t.Fatal("default group should block users not in 'users'")
	}
	if !a.Permit("/x", "u", []string{"users"}) {
		t.Fatal("default group should allow members of 'users'")
	}
}
