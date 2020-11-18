package pkg

import (
	"fmt"

	"github.com/anchore/syft/internal"
	"github.com/facebookincubator/nvdtools/wfn"
)

type CPE = wfn.Attributes

func NewCPE(cpeStr string) (CPE, error) {
	value, err := wfn.Parse(cpeStr)
	if err != nil {
		return CPE{}, fmt.Errorf("failed to parse CPE=%q: %w", cpeStr, err)
	}

	if value == nil {
		return CPE{}, fmt.Errorf("failed to parse CPE=%q", cpeStr)
	}

	// we need to compare the raw data since we are constructing CPEs in other locations
	value.Vendor = wfn.StripSlashes(value.Vendor)
	value.Product = wfn.StripSlashes(value.Product)
	value.Language = wfn.StripSlashes(value.Language)
	value.Version = wfn.StripSlashes(value.Version)
	value.TargetSW = wfn.StripSlashes(value.TargetSW)
	value.Part = wfn.StripSlashes(value.Part)
	value.Edition = wfn.StripSlashes(value.Edition)
	value.Other = wfn.StripSlashes(value.Other)
	value.SWEdition = wfn.StripSlashes(value.SWEdition)
	value.TargetHW = wfn.StripSlashes(value.TargetHW)
	value.Update = wfn.StripSlashes(value.Update)

	return *value, nil
}

const any = "*"

//// TODO: would be great to allow these to be overridden by user data/config
//var targetSoftware = map[Language][]string{
//	Java: {
//		"java",
//		"maven",
//		"jenkins",
//		"cloudbees_jenkins",
//	},
//	//JavaScript: {
//	//	"node.js",
//	//},
//	Python: {
//		"python",
//	},
//	Ruby: {
//		"ruby",
//		"rails",
//	},
//}

type CPEFieldCandidates struct {
	Vendor   []string
	Product  []string
	TargetSW []string
}

// GenerateCPEs Create a list of CPEs, trying to guess the vendor, product tuple and setting TargetSoftware if possible
func GenerateCPEs(name, version string, cfg *CPEFieldCandidates) []CPE {
	if cfg == nil {
		cfg = &CPEFieldCandidates{}
	}

	if cfg.Product == nil {
		cfg.Product = []string{name}
	}

	if cfg.Vendor == nil {
		cfg.Vendor = []string{name}
	}

	keys := internal.NewStringSet()
	cpes := make([]CPE, 0)
	for _, product := range cfg.Product {
		for _, vendor := range append([]string{any}, cfg.Vendor...) {
			for _, targetSw := range append([]string{any}, cfg.TargetSW...) {
				// prevent duplicate entries...
				key := fmt.Sprintf("%s|%s|%s|%s", product, vendor, version, targetSw)
				if keys.Contains(key) {
					continue
				}
				keys.Add(key)

				// add a new entry...
				candidateCpe := wfn.NewAttributesWithAny()
				candidateCpe.Product = product
				candidateCpe.Vendor = vendor
				candidateCpe.Version = version
				candidateCpe.TargetSW = targetSw

				cpes = append(cpes, *candidateCpe)
			}
		}
	}

	return cpes
}

//func candidateTargetSoftwareAttrs(p *pkg.Package) []string {
//	// TODO: expand with package metadata (from type assert)
//	mappedNames := targetSoftware[p.Language]
//
//	if mappedNames == nil {
//		mappedNames = []string{}
//	}
//
//	attrs := make([]string, len(mappedNames))
//	copy(attrs, targetSoftware[p.Language])
//	// last element is the any match, present for all
//	attrs = append(attrs, any)
//
//	return attrs
//}
//
//func candidateVendors(p *pkg.Package) []string {
//	// TODO: expand with package metadata (from type assert)
//	ret := []string{p.Name, any}
//	if p.Language == pkg.Python {
//		ret = append(ret, fmt.Sprintf("python-%s", p.Name))
//	}
//	return ret
//}

//
