import ipaddress

from django.core.exceptions import ValidationError
from django.contrib import admin
from django import forms

from scionlab_ixp.models import ASPeerPolicy, ISDPeerPolicy, IXP, IXPLink, IXPMember
from scionlab_ixp.peering_policy import apply_peering_policy


@admin.register(IXP)
class IXPAdmin(admin.ModelAdmin):
    fields = ['label', 'ip_network']
    list_display = ['id', 'label', 'ip_network']
    ordering = ['id']

    def get_readonly_fields(self, request, obj):
        if obj:
            return ('ip_network',) # Read-only in change forms.
        else:
            return ()


class IXPMemberAdminForm(forms.ModelForm):
    class Meta:
        model = IXPMember
        fields = ['ixp', 'host', 'public_ip', 'bind_ip']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['public_ip'].required = False # Allow an empty input string for 'public_ip'.

    def clean_public_ip(self):
        raw = self.cleaned_data['public_ip']

        if len(raw) == 0:
            public_ip = None # Assign IP in self.clean().
        else:
            try:
                public_ip = ipaddress.ip_address(self.cleaned_data['public_ip'])
            except ValueError:
                raise ValidationError("Invalid IP address.", code='invalid_public_ip')

        return public_ip

    def clean(self):
        cleaned_data = super().clean()

        # Automatically assign an IP address if the 'public_ip' field was empty.
        if 'public_ip' in cleaned_data and cleaned_data['public_ip'] is None:
            try:
                cleaned_data['public_ip'] = cleaned_data['ixp'].get_unused_ip()
            except KeyError:
                pass # ixp field is empty, will be caught later
            except IXP.AddressesExhausted:
                raise ValidationError(
                    {'public_ip': "Addresses exhausted."}, code='addresses_exhausted')

        return cleaned_data


@admin.register(IXPMember)
class IXPMemberAdmin(admin.ModelAdmin):
    form = IXPMemberAdminForm
    list_display = ['ixp', 'host', 'public_ip', 'bind_ip']
    ordering = ['ixp', 'host']


@admin.register(ASPeerPolicy)
class ASPeerPolicyAdmin(admin.ModelAdmin):
    fields = ['ixp', 'AS', 'peer_as', 'deny']
    list_display = ['ixp', 'AS', 'peer_as', 'get_policy_type']
    ordering = ['ixp', 'AS', 'deny', 'peer_as']
    list_filter = ['ixp', 'AS']

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        apply_peering_policy(obj.AS, obj.ixp)

    def delete_model(self, request, obj):
        super().delete_model(request, obj)
        apply_peering_policy(obj.AS, obj.ixp)

    def delete_queryset(self, request, queryset):
        update = {(obj.AS, obj.ixp) for obj in queryset}
        super().delete_queryset(request, queryset)
        for asys, ixp in update:
            apply_peering_policy(asys, ixp)


@admin.register(ISDPeerPolicy)
class ISDPeerPolicyAdmin(admin.ModelAdmin):
    fields = ['ixp', 'AS', 'peer_isd', 'deny']
    list_display = ['ixp', 'AS', 'peer_isd', 'get_policy_type']
    ordering = ['ixp', 'AS', 'deny', 'peer_isd']
    list_filter = ['ixp', 'AS']

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        apply_peering_policy(obj.AS, obj.ixp)

    def delete_model(self, request, obj):
        super().delete_model(request, obj)
        apply_peering_policy(obj.AS, obj.ixp)

    def delete_queryset(self, request, queryset):
        update = {(obj.AS, obj.ixp) for obj in queryset}
        super().delete_queryset(request, queryset)
        for asys, ixp in update:
            apply_peering_policy(asys, ixp)


admin.site.register([
    IXPLink
])
