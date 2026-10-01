Name:           ak-selfprov-test
Version:        2.0
Release:        1
Summary:        Artifact Keeper self-provided requires fixture
License:        MIT
BuildArch:      noarch
Provides:       ak-virt = 1.0
Provides:       ak-virt-unversioned
Requires:       ak-virt
Requires:       ak-virt = 1.0
Requires:       ak-virt = 0:1.0
Requires:       ak-virt-unversioned
Requires:       ak-selfprov-test = 2.0-1
Requires:       ak-selfprov-test
Requires(pre,preun): ak-mixed-dep
Requires(preun): ak-dup
Requires:       ak-dup
Requires:       /usr/share/ak-selfprov/README
Requires:       /usr/sbin/ak-selfprov

%description
Fixture: requires the package satisfies itself, and duplicate handling.

%install
mkdir -p %{buildroot}/usr/sbin %{buildroot}/usr/share/ak-selfprov
printf '#!/bin/sh\n' > %{buildroot}/usr/sbin/ak-selfprov
chmod 755 %{buildroot}/usr/sbin/ak-selfprov
echo doc > %{buildroot}/usr/share/ak-selfprov/README

%files
/usr/sbin/ak-selfprov
/usr/share/ak-selfprov/README
