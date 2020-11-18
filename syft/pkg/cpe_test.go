package pkg

import (
	"testing"
)

func must(c CPE, e error) CPE {
	if e != nil {
		panic(e)
	}
	return c
}

func TestNew(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected CPE
	}{
		{
			name:     "gocase",
			input:    `cpe:/a:10web:form_maker:1.0.0::~~~wordpress~~`,
			expected: must(NewCPE(`cpe:2.3:a:10web:form_maker:1.0.0:*:*:*:*:wordpress:*:*`)),
		},
		{
			name:     "dashes",
			input:    `cpe:/a:7-zip:7-zip:4.56:beta:~~~windows~~`,
			expected: must(NewCPE(`cpe:2.3:a:7-zip:7-zip:4.56:beta:*:*:*:windows:*:*`)),
		},
		{
			name:     "URL escape characters",
			input:    `cpe:/a:%240.99_kindle_books_project:%240.99_kindle_books:6::~~~android~~`,
			expected: must(NewCPE(`cpe:2.3:a:$0.99_kindle_books_project:$0.99_kindle_books:6:*:*:*:*:android:*:*`)),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := NewCPE(test.input)
			if err != nil {
				t.Fatalf("got an error while creating CPE: %+v", err)
			}

			if actual.BindToFmtString() != test.expected.BindToFmtString() {
				t.Errorf("mismatched entries:\n\texpected:%+v\n\t  actual:%+v\n", test.expected.BindToFmtString(), actual.BindToFmtString())
			}

		})
	}
}

func TestGenerate(t *testing.T) {
	tests := []struct {
		name     string
		p        pkg.Package
		expected []pkg.CPE
	}{
		{
			name: "simple package",
			p: pkg.Package{
				Name:     "name",
				Version:  "3.2",
				FoundBy:  "some-analyzer",
				Language: pkg.Java,
				Type:     pkg.DebPkg,
			},
			expected: []pkg.CPE{
				must(pkg.NewCPE("cpe:2.3:*:name:name:3.2:*:*:*:*:java:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name:name:3.2:*:*:*:*:maven:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name:name:3.2:*:*:*:*:jenkins:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name:name:3.2:*:*:*:*:cloudbees_jenkins:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:name:name:3.2:*:*:*:*:*:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:*:name:3.2:*:*:*:*:java:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:*:name:3.2:*:*:*:*:maven:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:*:name:3.2:*:*:*:*:jenkins:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:*:name:3.2:*:*:*:*:cloudbees_jenkins:*:*")),
				must(pkg.NewCPE("cpe:2.3:*:*:name:3.2:*:*:*:*:*:*:*")),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := GenerateCPEs(&test.p)
			if err != nil {
				t.Fatalf("got an error while generating CPEs: %+v", err)
			}

			if len(actual) != len(test.expected) {
				for _, e := range actual {
					t.Errorf("   unexpected entry: %+v", e.BindToFmtString())
				}
				t.Fatalf("unexpected number of entries: %d", len(actual))
			}

			for idx, a := range actual {
				e := test.expected[idx]
				if a.BindToFmtString() != e.BindToFmtString() {
					t.Errorf("mismatched entries @ %d:\n\texpected:%+v\n\t  actual:%+v\n", idx, e.BindToFmtString(), a.BindToFmtString())
				}
			}
		})
	}
}
