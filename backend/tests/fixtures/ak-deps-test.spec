Name:           ak-deps-test
Epoch:          2
Version:        1.5
Release:        3
Summary:        Artifact Keeper dependency metadata fixture
License:        MIT
Group:          Development/Tools
Vendor:         Artifact Keeper
Packager:       AK Tests <tests@example.invalid>
URL:            https://example.invalid/ak-deps-test
BuildArch:      noarch
Requires:       openssl11-custom-libs
Requires:       bash >= 4.2
Requires:       glibc-common < 3:2.40-1
Requires(pre):  shadow-utils
Requires(post): coreutils
Requires:       coreutils
Requires(posttrans): ak-posttrans-dep
Requires(preun): ak-preun-dep
Requires(pretrans): ak-pretrans-dep
Requires:       /usr/bin/ak-deps-tool
Provides:       ak-deps-virtual = 1.0
Provides:       webserver
Conflicts:      ak-old-conflict <= 0.9
Obsoletes:      ak-legacy-tool < 1.0-5
Recommends:     ak-extra
Suggests:       ak-docs

%description
Fixture exercising requires/provides/conflicts/obsoletes & weak deps.

%install
mkdir -p %{buildroot}/usr/bin %{buildroot}/etc/ak-deps %{buildroot}/usr/share/ak-deps
printf '#!/bin/sh\necho hi\n' > %{buildroot}/usr/bin/ak-deps-tool
chmod 755 %{buildroot}/usr/bin/ak-deps-tool
echo 'k=v' > %{buildroot}/etc/ak-deps/ak.conf
echo 'doc' > %{buildroot}/usr/share/ak-deps/README

%pre
exit 0

%files
/usr/bin/ak-deps-tool
%dir /etc/ak-deps
%config(noreplace) /etc/ak-deps/ak.conf
%ghost /etc/ak-deps/state.db
/usr/share/ak-deps/README

%changelog
* Sat Sep 26 2026 AK Tests <tests@example.invalid> - 2:1.5-3
- fixture
