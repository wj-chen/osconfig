package agentendpoint

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/GoogleCloudPlatform/guest-logging-go/logger"
	"github.com/GoogleCloudPlatform/osconfig/attributes"
	"github.com/GoogleCloudPlatform/osconfig/config"
	agentendpointpb "github.com/GoogleCloudPlatform/osconfig/internal/google.golang.org/genproto/googleapis/cloud/osconfig/agentendpoint/v1alpha1"
	"github.com/GoogleCloudPlatform/osconfig/inventory"
	"github.com/GoogleCloudPlatform/osconfig/packages"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	inventoryURL = config.ReportURL + "/guestInventory"
	maxRetries   = 5
)

// ReportInventory reports inventory to agent endpoint and writes it to guest attributes.
func (c *Client) ReportInventory(ctx context.Context) {
	state := inventory.Get()
	write(state, inventoryURL)
	c.report(ctx, state)
}

func write(state *inventory.InstanceInventory, url string) {
	logger.Debugf("Writing instance inventory to guest attributes.")

	e := reflect.ValueOf(state).Elem()
	t := e.Type()
	for i := 0; i < e.NumField(); i++ {
		f := e.Field(i)
		u := fmt.Sprintf("%s/%s", url, t.Field(i).Name)
		switch f.Kind() {
		case reflect.String:
			logger.Debugf("postAttribute %s: %+v", u, f)
			if err := attributes.PostAttribute(u, strings.NewReader(f.String())); err != nil {
				logger.Errorf("postAttribute error: %v", err)
			}
		case reflect.Struct:
			logger.Debugf("postAttributeCompressed %s: %+v", u, f)
			if err := attributes.PostAttributeCompressed(u, f.Interface()); err != nil {
				logger.Errorf("postAttributeCompressed error: %v", err)
			}
		}
	}
}

func (c *Client) report(ctx context.Context, state *inventory.InstanceInventory) {
	logger.Debugf("Reporting instance inventory to agent endpoint.")
	inventory := formatInventory(state)

	reportFull := false
	retries := 0
	for {
		res, err := c.reportInventory(ctx, inventory, reportFull)
		if err != nil {
			logger.Errorf("Error reporting inventory: %v", err)
		}

		if !res.GetReportFullInventory() {
			break
		} else {
			reportFull = true
		}

		retries++
		if retries >= maxRetries {
			logger.Errorf("Error reporting inventory: exceeded %d tries", maxRetries)
			break
		}
	}
}

func formatInventory(state *inventory.InstanceInventory) *agentendpointpb.Inventory {
	osInfo := &agentendpointpb.Inventory_OsInfo{
		HostName:             state.Hostname,
		LongName:             state.LongName,
		ShortName:            state.ShortName,
		Version:              state.Version,
		Architecture:         state.Architecture,
		KernelVersion:        state.KernelVersion,
		KernelRelease:        state.KernelRelease,
		OsconfigAgentVersion: state.OSConfigAgentVersion,
	}
	installedPackages := formatPackages(state.InstalledPackages, state.ShortName)
	availablePackages := formatPackages(state.PackageUpdates, state.ShortName)

	logger.Debugf("%v%v", osInfo, installedPackages)
	return &agentendpointpb.Inventory{OsInfo: osInfo, InstalledPackages: installedPackages, AvailablePackages: availablePackages}
}

func formatPackages(packages packages.Packages, shortName string) []*agentendpointpb.Inventory_SoftwarePackage {
	var softwarePackages []*agentendpointpb.Inventory_SoftwarePackage
	if packages.Apt != nil {
		for _, pkg := range packages.Apt {
			softwarePackages = append(softwarePackages, &agentendpointpb.Inventory_SoftwarePackage{
				Details: formatAptPackage(pkg),
			})
		}
	}
	if packages.GooGet != nil {
		for _, pkg := range packages.GooGet {
			softwarePackages = append(softwarePackages, &agentendpointpb.Inventory_SoftwarePackage{
				Details: formatGooGetPackage(pkg),
			})
		}
	}
	if packages.Yum != nil {
		for _, pkg := range packages.Yum {
			softwarePackages = append(softwarePackages, &agentendpointpb.Inventory_SoftwarePackage{
				Details: formatYumPackage(pkg),
			})
		}
	}
	if packages.Zypper != nil {
		for _, pkg := range packages.Zypper {
			softwarePackages = append(softwarePackages, &agentendpointpb.Inventory_SoftwarePackage{
				Details: formatZypperPackage(pkg),
			})
		}
	}
	if packages.ZypperPatches != nil {
		for _, pkg := range packages.ZypperPatches {
			softwarePackages = append(softwarePackages, &agentendpointpb.Inventory_SoftwarePackage{
				Details: formatZypperPatch(pkg),
			})
		}
	}
	if packages.WUA != nil {
		for _, pkg := range packages.WUA {
			softwarePackages = append(softwarePackages, &agentendpointpb.Inventory_SoftwarePackage{
				Details: formatWUAPackage(pkg),
			})
		}
	}
	if packages.QFE != nil {
		for _, pkg := range packages.QFE {
			softwarePackages = append(softwarePackages, &agentendpointpb.Inventory_SoftwarePackage{
				Details: formatQFEPackage(pkg),
			})
		}
	}
	// Map Deb packages to Apt packages.
	if packages.Deb != nil {
		for _, pkg := range packages.Deb {
			softwarePackages = append(softwarePackages, &agentendpointpb.Inventory_SoftwarePackage{
				Details: formatAptPackage(pkg),
			})
		}
	}
	// Map Rpm packages to Yum or Zypper packages depending on the OS.
	if packages.Rpm != nil {
		if shortName == "sles" {
			for _, pkg := range packages.Rpm {
				softwarePackages = append(softwarePackages, &agentendpointpb.Inventory_SoftwarePackage{
					Details: formatZypperPackage(pkg),
				})
			}
		} else {
			for _, pkg := range packages.Rpm {
				softwarePackages = append(softwarePackages, &agentendpointpb.Inventory_SoftwarePackage{
					Details: formatYumPackage(pkg),
				})
			}
		}
	}
	// Ignore Pip and Gem packages.

	return softwarePackages
}

func formatAptPackage(pkg packages.PkgInfo) *agentendpointpb.Inventory_SoftwarePackage_AptPackage {
	return &agentendpointpb.Inventory_SoftwarePackage_AptPackage{
		AptPackage: &agentendpointpb.Inventory_VersionedPackage{
			Name:         pkg.Name,
			Architecture: pkg.Arch,
			Version:      pkg.Version,
		}}
}

func formatGooGetPackage(pkg packages.PkgInfo) *agentendpointpb.Inventory_SoftwarePackage_GoogetPackage {
	return &agentendpointpb.Inventory_SoftwarePackage_GoogetPackage{
		GoogetPackage: &agentendpointpb.Inventory_VersionedPackage{
			Name:         pkg.Name,
			Architecture: pkg.Arch,
			Version:      pkg.Version,
		}}
}

func formatYumPackage(pkg packages.PkgInfo) *agentendpointpb.Inventory_SoftwarePackage_YumPackage {
	return &agentendpointpb.Inventory_SoftwarePackage_YumPackage{
		YumPackage: &agentendpointpb.Inventory_VersionedPackage{
			Name:         pkg.Name,
			Architecture: pkg.Arch,
			Version:      pkg.Version}}
}

func formatZypperPackage(pkg packages.PkgInfo) *agentendpointpb.Inventory_SoftwarePackage_ZypperPackage {
	return &agentendpointpb.Inventory_SoftwarePackage_ZypperPackage{
		ZypperPackage: &agentendpointpb.Inventory_VersionedPackage{
			Name:         pkg.Name,
			Architecture: pkg.Arch,
			Version:      pkg.Version}}
}

func formatZypperPatch(pkg packages.ZypperPatch) *agentendpointpb.Inventory_SoftwarePackage_ZypperPatch {
	return &agentendpointpb.Inventory_SoftwarePackage_ZypperPatch{
		ZypperPatch: &agentendpointpb.Inventory_ZypperPatch{
			Name:     pkg.Name,
			Category: pkg.Category,
			Severity: pkg.Severity,
			Summary:  pkg.Summary,
		}}
}

func formatWUAPackage(pkg packages.WUAPackage) *agentendpointpb.Inventory_SoftwarePackage_WuaPackage {
	var categories []*agentendpointpb.Inventory_WindowsUpdatePackage_WindowsUpdateCategory
	for idx, category := range pkg.Categories {
		categories = append(categories, &agentendpointpb.Inventory_WindowsUpdatePackage_WindowsUpdateCategory{
			Id:   pkg.CategoryIDs[idx],
			Name: category,
		})
	}

	// TODO: Populate supportUrls with MoreInfoUrls.
	supportUrls := []string{}

	return &agentendpointpb.Inventory_SoftwarePackage_WuaPackage{
		WuaPackage: &agentendpointpb.Inventory_WindowsUpdatePackage{
			Title:                    pkg.Title,
			Description:              pkg.Description,
			Categories:               categories,
			KbArticleIds:             pkg.KBArticleIDs,
			SupportUrls:              supportUrls,
			UpdateId:                 pkg.UpdateID,
			RevisionNumber:           pkg.RevisionNumber,
			LastDeploymentChangeTime: timestamppb.New(pkg.LastDeploymentChangeTime),
		}}
}

func formatQFEPackage(pkg packages.QFEPackage) *agentendpointpb.Inventory_SoftwarePackage_QfePackage {
	installedTime, err := time.Parse("1/2/2006", pkg.InstalledOn)
	if err != nil {
		logger.Errorf("Error parsing QFE InstalledOn date: %v", err)
	}

	return &agentendpointpb.Inventory_SoftwarePackage_QfePackage{
		QfePackage: &agentendpointpb.Inventory_WindowsQuickFixEngineeringPackage{
			Caption:     pkg.Caption,
			Description: pkg.Description,
			HotFixId:    pkg.HotFixID,
			InstalledOn: timestamppb.New(installedTime),
		}}
}
