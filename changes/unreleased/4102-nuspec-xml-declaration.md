---
section: Fixed
issues: [#4102, #3603]
---
- **Real NuGet packages' `.nuspec` manifests now parse; the XML declaration used to make them unreadable** (#4102, #3603). The shared `.nuspec` reader tried to skip the `<?xml ...?>` declaration by searching a trimmed copy of the text and slicing the original at that offset. That handed the XML parser `?>` plus the rest of the file for every manifest that has a declaration, which is every one `nuget pack` / `dotnet pack` writes, with or without a byte-order mark. Two things depend on this reader. Hosted scans of NuGet packages, however they were uploaded, lost their identity pin (#3603) and graded as partial. NuGet scan-on-proxy (#4102) could not establish what a real package was, so it withheld every one under fail-closed and never scanned under fail-open. The reader now hands the whole document to the parser, which skips the declaration itself, after cutting only a leading byte-order mark or whitespace.
