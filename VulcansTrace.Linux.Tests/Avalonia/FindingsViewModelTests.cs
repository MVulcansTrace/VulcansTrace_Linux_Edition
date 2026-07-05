using System;
using System.Collections.Generic;
using System.Linq;
using VulcansTrace.Linux.Avalonia.ViewModels;
using VulcansTrace.Linux.Core;
using VulcansTrace.Linux.Agent.Findings;
using Xunit;

namespace VulcansTrace.Linux.Tests.Avalonia;

public class FindingsViewModelTests
{
    [AvaloniaFact]
    public void LoadResults_PopulatesCountsAndFilters()
    {
        var vm = new FindingsViewModel();
        var result = new AnalysisResult
        {
            Findings =
            [
                new Finding
                {
                    Category = FindingCategories.PortScan,
                    Severity = Severity.High,
                    SourceHost = "192.168.1.10",
                    Target = "multi",
                    TimeRangeStart = DateTime.UnixEpoch,
                    TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
                    ShortDescription = "Port scan",
                    Details = "detail"
                },
                new Finding
                {
                    Category = FindingCategories.Beaconing,
                    Severity = Severity.Low,
                    SourceHost = "192.168.1.11",
                    Target = "10.0.0.2",
                    TimeRangeStart = DateTime.UnixEpoch,
                    TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(2),
                    ShortDescription = "Beaconing",
                    Details = "detail"
                }
            ],
            Warnings = ["warn-1"],
            ParseErrorCount = 1,
            ParseErrors = ["parse-error-1"],
            SkippedLineCount = 2
        };

        vm.LoadResults(result);

        Assert.Equal(2, vm.FindingsCount);
        Assert.Equal(1, vm.HighCriticalCount);
        Assert.Equal(1, vm.WarningCount);
        Assert.Equal(1, vm.ParseErrorCount);
        Assert.Equal(2, vm.SkippedLineCount);
        Assert.Equal(vm.Items.Count, vm.FilteredItems.Count);
        Assert.Single(vm.ParseErrors);
        Assert.Single(vm.Warnings);
    }

    [AvaloniaFact]
    public void SearchText_FiltersFindings()
    {
        var vm = new FindingsViewModel();
        var result = new AnalysisResult
        {
            Findings =
            [
                new Finding
                {
                    Category = FindingCategories.PortScan,
                    Severity = Severity.Medium,
                    SourceHost = "192.168.1.12",
                    Target = "multi",
                    TimeRangeStart = DateTime.UnixEpoch,
                    TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
                    ShortDescription = "Port scan detected",
                    Details = "detail"
                },
                new Finding
                {
                    Category = FindingCategories.Beaconing,
                    Severity = Severity.Medium,
                    SourceHost = "192.168.1.13",
                    Target = "10.0.0.9",
                    TimeRangeStart = DateTime.UnixEpoch,
                    TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
                    ShortDescription = "Periodic beacons",
                    Details = "detail"
                }
            ]
        };

        vm.LoadResults(result);
        vm.SearchText = "beacon";

        Assert.Single(vm.FilteredItems);
        Assert.Contains(vm.FilteredItems, item => item.Category == FindingCategories.Beaconing);
    }

    [AvaloniaFact]
    public void LoadResults_ClampsParseErrors()
    {
        var vm = new FindingsViewModel();
        var errors = Enumerable.Range(0, 205).Select(i => $"err-{i}").ToArray();
        var result = new AnalysisResult
        {
            ParseErrorCount = errors.Length,
            ParseErrors = errors
        };

        vm.LoadResults(result);

        Assert.Equal(201, vm.ParseErrors.Count);
        Assert.EndsWith("more parse errors not shown.", vm.ParseErrors[^1]);
    }

    [AvaloniaFact]
    public void LoadResults_PopulatesConfidenceAndEvidenceSignals()
    {
        var vm = new FindingsViewModel();
        var result = new AnalysisResult
        {
            Findings =
            [
                new Finding
                {
                    Category = FindingCategories.Beaconing,
                    Severity = Severity.High,
                    Confidence = DetectionConfidence.Confirmed,
                    SourceHost = "192.168.1.10",
                    Target = "10.0.0.5",
                    TimeRangeStart = DateTime.UnixEpoch,
                    TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
                    ShortDescription = "Beaconing detected",
                    Details = "detail",
                    EvidenceSignals =
                    [
                        new EvidenceSignal { Name = "Known malicious IP", Source = EvidenceSignal.ThreatIntelSource },
                        new EvidenceSignal { Name = "Beaconing pattern", Source = EvidenceSignal.BehaviorSource }
                    ]
                }
            ]
        };

        vm.LoadResults(result);

        var item = vm.Items.Single();
        Assert.Equal("Confirmed", item.Confidence);
        Assert.Contains("Known malicious IP", item.EvidenceSignalsDisplay);
        Assert.Contains("Beaconing pattern", item.EvidenceSignalsDisplay);
    }

    [AvaloniaFact]
    public void SearchText_FiltersByConfidence()
    {
        var vm = new FindingsViewModel();
        var result = new AnalysisResult
        {
            Findings =
            [
                new Finding
                {
                    Category = FindingCategories.PortScan,
                    Severity = Severity.Medium,
                    Confidence = DetectionConfidence.Low,
                    SourceHost = "192.168.1.12",
                    Target = "multi",
                    TimeRangeStart = DateTime.UnixEpoch,
                    TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
                    ShortDescription = "Port scan detected",
                    Details = "detail"
                },
                new Finding
                {
                    Category = FindingCategories.Beaconing,
                    Severity = Severity.Medium,
                    Confidence = DetectionConfidence.High,
                    SourceHost = "192.168.1.13",
                    Target = "10.0.0.9",
                    TimeRangeStart = DateTime.UnixEpoch,
                    TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
                    ShortDescription = "Periodic beacons",
                    Details = "detail"
                }
            ]
        };

        vm.LoadResults(result);
        vm.SearchText = "High";

        Assert.Single(vm.FilteredItems);
        Assert.Equal("Beaconing", vm.FilteredItems[0].Category);
    }

    [AvaloniaFact]
    public void SearchText_FiltersByEvidenceSignal()
    {
        var vm = new FindingsViewModel();
        var result = new AnalysisResult
        {
            Findings =
            [
                new Finding
                {
                    Category = FindingCategories.PortScan,
                    Severity = Severity.Medium,
                    Confidence = DetectionConfidence.Medium,
                    SourceHost = "192.168.1.12",
                    Target = "multi",
                    TimeRangeStart = DateTime.UnixEpoch,
                    TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
                    ShortDescription = "Port scan detected",
                    Details = "detail",
                    EvidenceSignals =
                    [
                        new EvidenceSignal { Name = "Many distinct ports", Source = "Behavior" }
                    ]
                },
                new Finding
                {
                    Category = FindingCategories.Beaconing,
                    Severity = Severity.Medium,
                    Confidence = DetectionConfidence.Medium,
                    SourceHost = "192.168.1.13",
                    Target = "10.0.0.9",
                    TimeRangeStart = DateTime.UnixEpoch,
                    TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
                    ShortDescription = "Periodic beacons",
                    Details = "detail",
                    EvidenceSignals =
                    [
                        new EvidenceSignal { Name = "Repeated destination", Source = "Behavior" }
                    ]
                }
            ]
        };

        vm.LoadResults(result);
        vm.SearchText = "Repeated destination";

        Assert.Single(vm.FilteredItems);
        Assert.Equal("Beaconing", vm.FilteredItems[0].Category);
    }

    [AvaloniaFact]
    public void SearchText_FiltersByMitreTechnique()
    {
        var vm = new FindingsViewModel();
        var result = new AnalysisResult
        {
            Findings =
            [
                new Finding
                {
                    Category = FindingCategories.PortScan,
                    Severity = Severity.Medium,
                    SourceHost = "192.168.1.12",
                    Target = "multi",
                    TimeRangeStart = DateTime.UnixEpoch,
                    TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
                    ShortDescription = "Port scan detected",
                    Details = "detail",
                    MitreTechniques =
                    [
                        new MitreTechnique { TechniqueId = "T1046" }
                    ]
                },
                new Finding
                {
                    Category = FindingCategories.Beaconing,
                    Severity = Severity.Medium,
                    SourceHost = "192.168.1.13",
                    Target = "10.0.0.9",
                    TimeRangeStart = DateTime.UnixEpoch,
                    TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
                    ShortDescription = "Periodic beacons",
                    Details = "detail",
                    MitreTechniques =
                    [
                        new MitreTechnique { TechniqueId = "T1071.001" }
                    ]
                }
            ]
        };

        vm.LoadResults(result);
        vm.SearchText = "T1071.001";

        Assert.Single(vm.FilteredItems);
        Assert.Equal("Beaconing", vm.FilteredItems[0].Category);
        Assert.Equal("T1071.001", vm.FilteredItems[0].MitreTechniquesDisplay);
    }

    [AvaloniaFact]
    public void FindingItemViewModel_TimeRangeDisplay_ShowsStartAndEnd()
    {
        var finding = new Finding
        {
            Category = FindingCategories.PortScan,
            Severity = Severity.High,
            SourceHost = "192.168.1.10",
            Target = "multi",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(7),
            ShortDescription = "Port scan",
            Details = "detail"
        };

        var item = new FindingItemViewModel(finding);

        Assert.Equal("1970-01-01 00:00 - 00:07", item.TimeRangeDisplay);
    }

    [AvaloniaFact]
    public void EmptyStateText_DistinguishesInitialAndCompletedEmptyResults()
    {
        var vm = new FindingsViewModel();

        Assert.False(vm.HasLoadedResults);
        Assert.Equal("No findings yet", vm.EmptyStateHeadline);

        vm.LoadResults(new AnalysisResult());

        Assert.True(vm.HasLoadedResults);
        Assert.False(vm.HasItems);
        Assert.Equal("No findings at this intensity", vm.EmptyStateHeadline);
        Assert.Contains("last run completed", vm.EmptyStateDescription);

        vm.Clear();

        Assert.False(vm.HasLoadedResults);
        Assert.Equal("No findings yet", vm.EmptyStateHeadline);
    }

    [AvaloniaTheory]
    [InlineData(1, "")]
    [InlineData(5, "×5")]
    [InlineData(438, "×438")]
    public void FindingItemViewModel_GroupBadge_OnlyShowsGroupedFindings(int groupedCount, string expectedBadge)
    {
        var finding = new Finding
        {
            Category = FindingCategories.PortScan,
            Severity = Severity.High,
            SourceHost = "192.168.1.10",
            Target = "multi",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            ShortDescription = "Port scan",
            Details = "detail",
            GroupedCount = groupedCount
        };

        var item = new FindingItemViewModel(finding);

        Assert.Equal(expectedBadge, item.GroupBadge);
    }

    [AvaloniaFact]
    public void Commands_CanBeSetAndRead()
    {
        var vm = new FindingsViewModel();
        var cmd = new RelayCommand(_ => { });

        vm.InvestigateCommand = cmd;
        vm.SuppressCommand = cmd;
        vm.ResolveCommand = cmd;

        Assert.Same(cmd, vm.InvestigateCommand);
        Assert.Same(cmd, vm.SuppressCommand);
        Assert.Same(cmd, vm.ResolveCommand);
    }

    [AvaloniaFact]
    public void SelectedFindingActionContext_DescribesToolbarTarget()
    {
        var vm = new FindingsViewModel();
        var result = new AnalysisResult
        {
            Findings =
            [
                new Finding
                {
                    RuleId = "FW-001",
                    Category = FindingCategories.PortScan,
                    Severity = Severity.High,
                    SourceHost = "192.168.1.10",
                    Target = "10.0.0.5",
                    TimeRangeStart = DateTime.UnixEpoch,
                    TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
                    ShortDescription = "Port scan",
                    Details = "detail"
                }
            ]
        };

        Assert.False(vm.HasSelectedItem);
        Assert.Equal("Select a finding to investigate, suppress, or resolve", vm.SelectedFindingActionContext);

        vm.LoadResults(result);
        vm.SelectedItem = vm.Items.Single();

        Assert.True(vm.HasSelectedItem);
        Assert.Equal("Selected: FW-001 - High - 192.168.1.10 -> 10.0.0.5", vm.SelectedFindingActionContext);

        vm.Clear();

        Assert.False(vm.HasSelectedItem);
        Assert.Equal("Select a finding to investigate, suppress, or resolve", vm.SelectedFindingActionContext);
    }

    [AvaloniaTheory]
    [InlineData(1)]
    [InlineData(5)]
    [InlineData(438)]
    public void FindingItemViewModel_GroupedCount_AlwaysShowsRawCount(int groupedCount)
    {
        var finding = new Finding
        {
            Category = FindingCategories.PortScan,
            Severity = Severity.High,
            SourceHost = "192.168.1.10",
            Target = "multi",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            ShortDescription = "Port scan",
            Details = "detail",
            GroupedCount = groupedCount
        };

        var item = new FindingItemViewModel(finding);

        Assert.Equal(groupedCount, item.GroupedCount);
    }

    [AvaloniaFact]
    public void LoadResults_MarksPinnedItemsFromStore()
    {
        var store = new InMemoryPinnedFindingStore();
        var finding = new Finding
        {
            Category = FindingCategories.PortScan,
            Severity = Severity.High,
            SourceHost = "192.168.1.10",
            Target = "multi",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            ShortDescription = "Port scan",
            Details = "detail"
        };
        store.Pin(new PinnedFinding
        {
            Fingerprint = finding.Fingerprint,
            Category = finding.Category,
            Severity = finding.Severity.ToString(),
            SourceHost = finding.SourceHost,
            Target = finding.Target,
            ShortDescription = finding.ShortDescription
        });

        var vm = new FindingsViewModel(store);
        vm.LoadResults(new AnalysisResult { Findings = [finding] });

        Assert.True(vm.Items.Single().IsPinned);
        Assert.Equal(1, vm.PinnedCount);
        Assert.True(vm.HasPinnedFindings);
    }

    [AvaloniaFact]
    public void PinCommand_PinsFindingAndUpdatesCount()
    {
        var store = new InMemoryPinnedFindingStore();
        var vm = new FindingsViewModel(store);
        var finding = new Finding
        {
            Category = FindingCategories.PortScan,
            Severity = Severity.High,
            SourceHost = "192.168.1.10",
            Target = "multi",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            ShortDescription = "Port scan",
            Details = "detail"
        };
        vm.LoadResults(new AnalysisResult { Findings = [finding] });
        var item = vm.Items.Single();

        Assert.False(item.IsPinned);
        Assert.True(vm.PinCommand.CanExecute(item));
        Assert.False(vm.UnpinCommand.CanExecute(item));

        vm.PinCommand.Execute(item);

        Assert.True(item.IsPinned);
        Assert.Equal(1, vm.PinnedCount);
        Assert.True(store.IsPinned(finding.Fingerprint));
    }

    [AvaloniaFact]
    public void UnpinCommand_RemovesPinAndUpdatesCount()
    {
        var store = new InMemoryPinnedFindingStore();
        var vm = new FindingsViewModel(store);
        var finding = new Finding
        {
            Category = FindingCategories.PortScan,
            Severity = Severity.High,
            SourceHost = "192.168.1.10",
            Target = "multi",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            ShortDescription = "Port scan",
            Details = "detail"
        };
        vm.LoadResults(new AnalysisResult { Findings = [finding] });
        var item = vm.Items.Single();
        vm.PinCommand.Execute(item);

        vm.UnpinCommand.Execute(item);

        Assert.False(item.IsPinned);
        Assert.Equal(0, vm.PinnedCount);
        Assert.False(store.IsPinned(finding.Fingerprint));
    }

    [AvaloniaFact]
    public void ShowPinnedOnly_FiltersToPinned()
    {
        var store = new InMemoryPinnedFindingStore();
        var vm = new FindingsViewModel(store);
        var pinned = new Finding
        {
            Category = FindingCategories.PortScan,
            Severity = Severity.High,
            SourceHost = "192.168.1.10",
            Target = "multi",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            ShortDescription = "Pinned port scan",
            Details = "detail"
        };
        var unpinned = new Finding
        {
            Category = FindingCategories.Beaconing,
            Severity = Severity.Medium,
            SourceHost = "192.168.1.11",
            Target = "10.0.0.2",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            ShortDescription = "Beaconing",
            Details = "detail"
        };
        vm.LoadResults(new AnalysisResult { Findings = [pinned, unpinned] });
        vm.PinCommand.Execute(vm.Items[0]);

        vm.ShowPinnedOnly = true;

        Assert.Single(vm.FilteredItems);
        Assert.Equal("PortScan", vm.FilteredItems[0].Category);
    }

    [AvaloniaFact]
    public void ShowPinnedOnly_StillAppliesSearchText()
    {
        var store = new InMemoryPinnedFindingStore();
        var vm = new FindingsViewModel(store);
        var pinnedA = new Finding
        {
            Category = FindingCategories.PortScan,
            Severity = Severity.High,
            SourceHost = "192.168.1.10",
            Target = "multi",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            ShortDescription = "Pinned port scan",
            Details = "detail"
        };
        var pinnedB = new Finding
        {
            Category = FindingCategories.Beaconing,
            Severity = Severity.Medium,
            SourceHost = "192.168.1.11",
            Target = "10.0.0.2",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            ShortDescription = "Pinned beaconing",
            Details = "detail"
        };
        vm.LoadResults(new AnalysisResult { Findings = [pinnedA, pinnedB] });
        vm.PinCommand.Execute(vm.Items[0]);
        vm.PinCommand.Execute(vm.Items[1]);

        vm.ShowPinnedOnly = true;
        vm.SearchText = "beacon";

        Assert.Single(vm.FilteredItems);
        Assert.Equal("Beaconing", vm.FilteredItems[0].Category);
    }

    [AvaloniaFact]
    public void Clear_DoesNotRemovePersistedPins()
    {
        var store = new InMemoryPinnedFindingStore();
        var vm = new FindingsViewModel(store);
        var finding = new Finding
        {
            Category = FindingCategories.PortScan,
            Severity = Severity.High,
            SourceHost = "192.168.1.10",
            Target = "multi",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            ShortDescription = "Port scan",
            Details = "detail"
        };
        vm.LoadResults(new AnalysisResult { Findings = [finding] });
        vm.PinCommand.Execute(vm.Items.Single());

        vm.Clear();

        Assert.True(store.IsPinned(finding.Fingerprint));
        Assert.Equal(0, vm.PinnedCount);
        Assert.False(vm.HasPinnedFindings);
    }

    [AvaloniaFact]
    public void TogglePinSelectedCommand_PinsAndUnpinsSelectedFinding()
    {
        var store = new InMemoryPinnedFindingStore();
        var vm = new FindingsViewModel(store);
        var finding = new Finding
        {
            Category = FindingCategories.PortScan,
            Severity = Severity.High,
            SourceHost = "192.168.1.10",
            Target = "multi",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            ShortDescription = "Port scan",
            Details = "detail"
        };
        vm.LoadResults(new AnalysisResult { Findings = [finding] });
        var item = vm.Items.Single();

        Assert.False(vm.TogglePinSelectedCommand.CanExecute(null));

        vm.SelectedItem = item;

        Assert.True(vm.TogglePinSelectedCommand.CanExecute(null));

        vm.TogglePinSelectedCommand.Execute(null);

        Assert.True(item.IsPinned);
        Assert.Equal(1, vm.PinnedCount);
        Assert.True(store.IsPinned(finding.Fingerprint));

        vm.TogglePinSelectedCommand.Execute(null);

        Assert.False(item.IsPinned);
        Assert.Equal(0, vm.PinnedCount);
        Assert.False(store.IsPinned(finding.Fingerprint));
    }

    [AvaloniaFact]
    public void TogglePinSelectedCommand_DoesNothingWhenNothingSelected()
    {
        var store = new InMemoryPinnedFindingStore();
        var vm = new FindingsViewModel(store);
        var finding = new Finding
        {
            Category = FindingCategories.PortScan,
            Severity = Severity.High,
            SourceHost = "192.168.1.10",
            Target = "multi",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            ShortDescription = "Port scan",
            Details = "detail"
        };
        vm.LoadResults(new AnalysisResult { Findings = [finding] });

        vm.TogglePinSelectedCommand.Execute(null);

        Assert.Equal(0, vm.PinnedCount);
        Assert.False(vm.Items.Single().IsPinned);
    }

    [AvaloniaFact]
    public void TogglePinSelectedCommand_TogglesThroughShowPinnedOnly()
    {
        var store = new InMemoryPinnedFindingStore();
        var vm = new FindingsViewModel(store);
        var pinned = new Finding
        {
            Category = FindingCategories.PortScan,
            Severity = Severity.High,
            SourceHost = "192.168.1.10",
            Target = "multi",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            ShortDescription = "Port scan",
            Details = "detail"
        };
        var unpinned = new Finding
        {
            Category = FindingCategories.Beaconing,
            Severity = Severity.Medium,
            SourceHost = "192.168.1.11",
            Target = "10.0.0.2",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            ShortDescription = "Beaconing",
            Details = "detail"
        };
        vm.LoadResults(new AnalysisResult { Findings = [pinned, unpinned] });
        vm.SelectedItem = vm.Items[1];
        vm.ShowPinnedOnly = true;

        // Pin the currently selected (second) item while pinned-only filter is active.
        vm.TogglePinSelectedCommand.Execute(null);

        Assert.True(vm.Items[1].IsPinned);
        Assert.Equal(1, vm.PinnedCount);
        // Once pinned, the newly pinned item qualifies for the pinned-only filter.
        Assert.Single(vm.FilteredItems);
        Assert.Same(vm.Items[1], vm.FilteredItems[0]);
    }

    [AvaloniaFact]
    public void AddFinding_WithPersistedPin_UpdatesPinnedCountAndEnablesPinnedOnlyFilter()
    {
        var store = new InMemoryPinnedFindingStore();
        var finding = new Finding
        {
            Category = FindingCategories.PortScan,
            Severity = Severity.High,
            SourceHost = "192.168.1.10",
            Target = "multi",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            ShortDescription = "Port scan",
            Details = "detail"
        };
        store.Pin(FindingsViewModel.CreatePinnedFinding(new FindingItemViewModel(finding)));

        var vm = new FindingsViewModel(store);
        Assert.Equal(0, vm.PinnedCount);
        Assert.False(vm.TogglePinnedOnlyCommand.CanExecute(null));

        vm.AddFinding(finding);

        Assert.True(vm.Items.Single().IsPinned);
        Assert.Equal(1, vm.PinnedCount);
        Assert.True(vm.HasPinnedFindings);
        Assert.True(vm.TogglePinnedOnlyCommand.CanExecute(null));
    }

    [AvaloniaFact]
    public void UnpinLastFinding_WhilePinnedOnly_LeavesButtonEnabledSoUserCanExit()
    {
        var store = new InMemoryPinnedFindingStore();
        var vm = new FindingsViewModel(store);
        var finding = new Finding
        {
            Category = FindingCategories.PortScan,
            Severity = Severity.High,
            SourceHost = "192.168.1.10",
            Target = "multi",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            ShortDescription = "Port scan",
            Details = "detail"
        };
        vm.LoadResults(new AnalysisResult { Findings = [finding] });
        var item = vm.Items.Single();
        vm.PinCommand.Execute(item);
        vm.ShowPinnedOnly = true;

        vm.UnpinCommand.Execute(item);

        Assert.Empty(vm.FilteredItems);
        Assert.True(vm.TogglePinnedOnlyCommand.CanExecute(null));
    }

    [AvaloniaFact]
    public void Constructor_WithPinnedPersistenceWarning_SurfacesPinStatus()
    {
        var vm = new FindingsViewModel(new InMemoryPinnedFindingStore("Pinned findings persistence is unavailable."));

        Assert.True(vm.HasPinStatusMessage);
        Assert.Equal("Pinned findings persistence is unavailable.", vm.PinStatusMessage);
    }

    [AvaloniaFact]
    public void PinCommand_SaveWarning_SurfacesPinStatusAndKeepsSessionPin()
    {
        var store = new WarningPinnedFindingStore("Could not save pinned findings to disk: boom. Pins will last only for this session.");
        var vm = new FindingsViewModel(store);
        var finding = new Finding
        {
            Category = FindingCategories.PortScan,
            Severity = Severity.High,
            SourceHost = "192.168.1.10",
            Target = "multi",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            ShortDescription = "Port scan",
            Details = "detail"
        };
        vm.LoadResults(new AnalysisResult { Findings = [finding] });
        var item = vm.Items.Single();

        vm.PinCommand.Execute(item);

        Assert.True(item.IsPinned);
        Assert.Equal(1, vm.PinnedCount);
        Assert.True(vm.HasPinStatusMessage);
        Assert.Contains("Pins will last only for this session", vm.PinStatusMessage);
    }

    [AvaloniaFact]
    public void PinCommand_RejectedByStore_DoesNotMarkItemPinned()
    {
        var store = new RejectingPinnedFindingStore("Could not save pinned findings to disk: invalid pin.");
        var vm = new FindingsViewModel(store);
        var finding = new Finding
        {
            Category = FindingCategories.PortScan,
            Severity = Severity.High,
            SourceHost = "192.168.1.10",
            Target = "multi",
            TimeRangeStart = DateTime.UnixEpoch,
            TimeRangeEnd = DateTime.UnixEpoch.AddMinutes(1),
            ShortDescription = "Port scan",
            Details = "detail"
        };
        vm.LoadResults(new AnalysisResult { Findings = [finding] });
        var item = vm.Items.Single();

        vm.PinCommand.Execute(item);

        Assert.False(item.IsPinned);
        Assert.Equal(0, vm.PinnedCount);
        Assert.True(vm.HasPinStatusMessage);
        Assert.Contains("invalid pin", vm.PinStatusMessage);
    }

    private sealed class WarningPinnedFindingStore : IPinnedFindingStore
    {
        private readonly Dictionary<string, PinnedFinding> _entries = new(StringComparer.OrdinalIgnoreCase);
        private readonly string _warning;

        public WarningPinnedFindingStore(string warning)
        {
            _warning = warning;
        }

        public string? PersistenceWarning { get; private set; }

        public void Pin(PinnedFinding finding)
        {
            _entries[finding.Fingerprint] = finding;
            PersistenceWarning = _warning;
        }

        public void Unpin(string fingerprint)
        {
            _entries.Remove(fingerprint);
            PersistenceWarning = _warning;
        }

        public bool IsPinned(string fingerprint) => _entries.ContainsKey(fingerprint);

        public IReadOnlyList<PinnedFinding> GetAll() => _entries.Values.ToList();
    }

    private sealed class RejectingPinnedFindingStore : IPinnedFindingStore
    {
        private readonly string _warning;

        public RejectingPinnedFindingStore(string warning)
        {
            _warning = warning;
        }

        public string? PersistenceWarning { get; private set; }

        public void Pin(PinnedFinding finding)
        {
            PersistenceWarning = _warning;
        }

        public void Unpin(string fingerprint)
        {
            PersistenceWarning = _warning;
        }

        public bool IsPinned(string fingerprint) => false;

        public IReadOnlyList<PinnedFinding> GetAll() => Array.Empty<PinnedFinding>();
    }
}
