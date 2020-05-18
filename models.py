import ipaddress

from django.core.exceptions import ValidationError
from django.db import models

from scionlab.defines import DEFAULT_LINK_BANDWIDTH, DEFAULT_LINK_MTU
from scionlab.models.core import Host, ISD, Link
from scionlab.models.user_as import UserAS

_MAX_IXP_LABEL_LEN = 255
_MAX_LEN_IP_SUBNET = 48


class IXP(models.Model):
    """Represents an IXP VLAN."""
    id = models.AutoField(primary_key=True, verbose_name="ID")
    label = models.CharField(
        max_length=_MAX_IXP_LABEL_LEN,
        null=True,
        blank=True,
        verbose_name="Label")
    ip_network = models.CharField(max_length=_MAX_LEN_IP_SUBNET)

    class Meta:
        verbose_name = 'IXP'
        verbose_name_plural = 'IXPs'

    class AddressesExhausted(Exception):
        def __init__(self):
            super().__init__('IXP IP addresses exhausted')

    def __str__(self):
        if self.label:
            return '%s (ID %d)' % (self.label, self.id)
        else:
            return 'IXP %d' % self.id

    def clean(self):
        try:
            ipaddress.ip_network(self.ip_network)
        except ValueError:
            raise ValidationError({'ip_network': "Invalid IP network."}, code='invalid_subnet')

    def get_ip_network(self):
        """Returns 'ip_network' as an instance of ipaddress.IPv4Network or ipaddress.IPv6Network."""
        return ipaddress.ip_network(self.ip_network)

    def get_unused_ip(self):
        """Get an unused IP address from the IXP's subnet."""
        raw_ips = IXPMember.objects.filter(ixp=self).values_list('public_ip', flat=True)
        ips_in_use = {ipaddress.ip_address(ip) for ip in raw_ips}

        for ip in self.get_ip_network().hosts():
            if ip not in ips_in_use:
                return ip
        else:
            raise self.AddressesExhausted()


class IXPLinkManager(models.Manager):
    def create(self, type, interfaceA, interfaceB, ixp, active=True, bandwidth=None, mtu=None):
        return super().create(
            type=type,
            active=active,
            bandwidth=bandwidth or DEFAULT_LINK_BANDWIDTH,
            mtu=mtu or DEFAULT_LINK_MTU,
            interfaceA=interfaceA,
            interfaceB=interfaceB,
            ixp=ixp
        )


class IXPLink(Link):
    """Tags links with the IXP they use."""
    ixp = models.ForeignKey(
        IXP,
        on_delete=models.CASCADE,
        related_name='links',
        verbose_name="IXP"
    )

    objects = IXPLinkManager()

    class Meta:
        verbose_name = 'IXP Link'

    def __str__(self):
        return '%s [%s]' % (super().__str__(), self.ixp)


class IXPMember(models.Model):
    """Defines which user ASes are connected to which IXPs.

    UserASes are represented by their one and only host.
    """
    ixp = models.ForeignKey(
        IXP,
        on_delete=models.CASCADE,
        verbose_name="IXP"
    )
    host = models.ForeignKey(
        Host,
        on_delete=models.CASCADE
    )
    public_ip = models.GenericIPAddressField()
    bind_ip = models.GenericIPAddressField(
        null=True,
        blank=True
    )

    class Meta:
        unique_together = [['ixp', 'host']]
        verbose_name = 'IXP Member'

    def __str__(self):
        return '%s is member of IXP %s' % (self.host, self.ixp)

    def get_public_ip(self):
        """Returns 'public_ip' as an instance of ipaddress.IPv4Address or ipaddress.IPv6Address."""
        return ipaddress.ip_address(self.public_ip)

    def clean(self):
        try:
            if self.host.AS.is_infrastructure_AS():
                raise ValidationError(
                    {'host': "Host does not belong to a user AS."}, code='not_a_user_as')
        except Host.DoesNotExist:
            return # host is empty, will be caught during form validation.

        if self.public_ip is not None:
            try:
                if self.get_public_ip() not in self.ixp.get_ip_network():
                    raise ValidationError(
                        {'public_ip': "Address is not from the IXP's subnet."},
                        code='invalid_public_ip')
            except IXP.DoesNotExist:
                return # ixp is empty, will be caught during form validation.

        try:
            if IXPMember.objects.filter(ixp=self.ixp, public_ip=self.public_ip):
                raise ValidationError(
                    {'public_ip': "IP is in use by another AS."}, code='ip_in_use')
        except IXP.DoesNotExist:
            return # ixp is empty, will be caught during form validation.


class PeeringPolicy(models.Model):
    """Base class for AS and ISD based peering policies."""
    AS = models.ForeignKey(
        UserAS,
        on_delete=models.CASCADE
    )
    deny = models.BooleanField(default=False)
    ixp = models.ForeignKey(
        IXP,
        on_delete=models.CASCADE,
        verbose_name="IXP"
    )

    class Meta:
        abstract = True

    def save(self, **kwargs):
        self.full_clean()
        super().save(**kwargs)

    def clean(self):
        try:
            # Make sure the AS is actually connected to the IXP
            if not IXPMember.objects.filter(ixp=self.ixp, host__AS=self.AS):
                raise ValidationError(
                    "%(asys)s is not a member of %(ixp)s.",
                    params={'asys': self.AS, 'ixp': self.ixp},
                    code='not_connected_to_ixp')
        except (IXP.DoesNotExist, UserAS.DoesNotExist):
            pass # AS or ixp is empty, will be caught during form validation.

    def get_policy_type(self):
        if not self.deny:
            return "Accept"
        else:
            return "Deny"
    get_policy_type.admin_order_field = 'deny'
    get_policy_type.short_description = "Type"


class ASPeerPolicy(PeeringPolicy):
    """AS accept/deny policy."""
    peer_as = models.ForeignKey(
        UserAS,
        related_name='+',
        on_delete=models.CASCADE,
        verbose_name="Peer AS"
    )

    class Meta:
        unique_together = ['ixp', 'AS', 'peer_as']
        verbose_name = 'AS Peering Policy'
        verbose_name_plural = 'AS Peering Policies'

    def clean(self):
        super().clean()
        try:
            if self.AS == self.peer_as:
                raise ValidationError("AS and peer AS are identical.", code='peer_with_self')
        except UserAS.DoesNotExist:
            pass # AS or peer_as is empty, will be caught during form validation.

    def __str__(self):
        if not self.deny:
            return "Accept %s -> %s (%s)" % (self.AS, self.peer_as, self.ixp)
        else:
            return "Deny %s -> %s (%s)" % (self.AS, self.peer_as, self.ixp)


class ISDPeerPolicy(PeeringPolicy):
    """ISD accept/deny policy."""
    peer_isd = models.ForeignKey(
        ISD,
        related_name='+',
        on_delete=models.CASCADE,
        verbose_name="Peer ISD"
    )

    class Meta:
        unique_together = ['ixp', 'AS', 'peer_isd']
        verbose_name = 'ISD Peering Policy'
        verbose_name_plural = 'ISD Peering Policies'

    def __str__(self):
        if not self.deny:
            return "Accept %s -> %s (%s)" % (self.AS, self.peer_isd, self.ixp)
        else:
            return "Deny %s -> %s (%s)" % (self.AS, self.peer_isd, self.ixp)
