import ipaddress
from typing import Set, Union

from django.db import transaction
from django.db.models import Q
from scionlab.models.core import BorderRouter, Host, Interface, Link
from scionlab.models.user_as import UserAS

from scionlab_ixp.models import ASPeerPolicy, ISDPeerPolicy, IXP, IXPLink, IXPMember


_MAX_PEERING_PER_BR = 10
"""Maximum number of peering links per border router."""

_IpAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


@transaction.atomic
def apply_peering_policy(asys: UserAS, ixp: IXP, *,
                         max_peering_per_br=_MAX_PEERING_PER_BR) -> None:
    """Create and delete peering links according to the peering policies of `asys`.

    :param asys: The AS whose peering rules are applied.
    :param ixp: IXP in which to create and/or delete links.
    :param max_peering_per_br: Maximum number of peering links per border router.
    """
    host = _get_peering_host(asys, ixp)
    candidate_set = _create_candidate_set(asys, ixp)
    modified_ases = set()

    # Remove all links to ASes not in the candidate set
    for link in IXPLink.objects.filter(interfaceA__host=host, type=Link.PEER, ixp=ixp):
        if link.interfaceB.AS not in candidate_set:
            link.delete()
            modified_ases.add(asys)
            modified_ases.add(link.interfaceB.AS.useras)
    for link in IXPLink.objects.filter(interfaceB__host=host, type=Link.PEER, ixp=ixp):
        if link.interfaceA.AS not in candidate_set:
            link.delete()
            modified_ases.add(asys)
            modified_ases.add(link.interfaceA.AS.useras)

    # Add new links
    for peer_as in candidate_set:
        peer_host = _get_peering_host(peer_as, ixp)
        if not _is_in_candidate_set(peer_as, asys, ixp):
            continue # other AS is not interested
        if IXPLink.objects.filter(interfaceA__host=host, interfaceB__host=peer_host, ixp=ixp):
            continue # link exists already
        if IXPLink.objects.filter(interfaceA__host=peer_host, interfaceB__host=host, ixp=ixp):
            continue # link exists already
        _create_link(asys, peer_as, ixp)
        modified_ases.add(asys)
        modified_ases.add(peer_as)

    for asys in modified_ases:
        _balance_peering_links(asys, max_peering_per_br)


def _create_candidate_set(asys: UserAS, ixp: IXP) -> Set[UserAS]:
    """Creates a set of user ASes the given AS is willing to peer with.

    :param asys: User AS for which to generate the peering candidate set.
    :param ixp: The IXP for which to evaluate the ASes peering rules.
    """
    candidate_set = set()
    # Add ASes from whitelisted ISDs
    for policy in ISDPeerPolicy.objects.filter(AS=asys, deny=False, ixp=ixp):
        for peer_as in UserAS.objects.filter(isd=policy.peer_isd):
            if peer_as != asys: # don't add the AS itself
                candidate_set.add(peer_as)

    # The order individually white- and blacklisted ASes are added/removed in does not matter,
    # because an AS cannot be white- *and* blacklisted at the same time.

    # Remove individually blacklisted ASes
    for policy in ASPeerPolicy.objects.filter(AS=asys, deny=True, ixp=ixp):
        candidate_set.discard(policy.peer_as)

    # Add individually whitelisted ASes
    for policy in ASPeerPolicy.objects.filter(AS=asys, deny=False, ixp=ixp):
        candidate_set.add(policy.peer_as)

    return candidate_set


def _is_in_candidate_set(asys: UserAS, peer_as: UserAS, ixp: IXP) -> bool:
    """Check whether `peer_as` is in the peering candidate set of `asys`.

    :param ixp: The IXP for which to evaluate the ASes peering rules.
    """
    # Check in reverse order of how _create_candidate_set() constructs the candidate sets to
    # maintain consitency between the two functions.

    if ASPeerPolicy.objects.filter(AS=asys, peer_as=peer_as, deny=False, ixp=ixp):
        return True # Peer AS is whitelisted

    if ASPeerPolicy.objects.filter(AS=asys, peer_as=peer_as, deny=True, ixp=ixp):
        return False # Peer AS is blacklisted

    if ISDPeerPolicy.objects.filter(AS=asys, peer_isd=peer_as.isd, deny=False, ixp=ixp):
        return True # ISD is whitelisted

    return False # ISD is blacklisted or there is no rule


def _create_link(as1: UserAS, as2: UserAS, ixp: IXP) -> IXPLink:
    """Create a new peering link between `as1` and `as2`.

    :param ixp: The IXP the link is established over.
    """
    if1 = _create_peering_interface(as1, ixp)
    if2 = _create_peering_interface(as2, ixp)
    return IXPLink.objects.create(Link.PEER, if1, if2, ixp)


def _create_peering_interface(asys: UserAS, ixp: IXP):
    """Create an interface on the border router designated for peering connections.

    :param asys: AS to create the interface in.
    :param ixp: IXP the link established over the new interface will belong to.
    """
    br = _get_peering_br(asys)
    ip = IXPMember.objects.filter(ixp=ixp, host=br.host).values_list('public_ip', flat=True)[0]
    port = _find_free_port(asys, ipaddress.ip_address(ip), 50000, 51000)
    return br.interfaces.create(public_ip=str(ip), public_port=port)


def _find_free_port(asys: UserAS, ip: _IpAddress, first_port: int, last_port: int) -> int:
    """Search for a free UDP port in the given user AS.

    :param ip: IP address the port should belong to.
    :param first_port: First port number to consider.
    :param last_port: One past the last port number to consider.
    :raises RuntimeError: No ports in the given range are free.
    """
    ports = set(asys.interfaces.filter(public_ip=str(ip)).values_list('public_port', flat=True))
    for port in range(first_port, last_port):
        if port not in ports:
            return port
    raise RuntimeError('No free port available')


def _get_peering_host(user_as: UserAS, ixp: IXP) -> Host:
    """Returns one of the AS's hosts connected to the given IXP."""
    # At the moment user ASes have only one host.
    return user_as.hosts.filter(ixpmember__ixp=ixp).first()


def _get_peering_br(user_as: UserAS) -> BorderRouter:
    """
    Returns the first border of `user_as` not connected to an infrastructure AS.
    If no such BR exists, a new one is created.
    """
    for br in BorderRouter.objects.filter(host=user_as.host):
        for iface in Interface.objects.filter(border_router=br):
            if iface.remote_interface().AS.is_infrastructure_AS():
                break
        else:
            return br

    return user_as.host.border_routers.create(host=user_as.host)


def _balance_peering_links(asys: UserAS, max_peering_per_br: int) -> None:
    """Distribute peering links over border routers so that no router has more than
    `max_peering_per_br` links and at most one has less.

    Border routers are created or delete if necessary.

    :param asys: AS whose peering links to balance.
    :param max_peering_per_br: Maximum number of peering links per border router.
    """
    # Get all border routers with IXP peering links or without any links
    brs = []
    for br in BorderRouter.objects.filter(host=asys.host):
        ifs = Interface.objects.filter(border_router=br)
        if len(ifs) == 0:
            brs.append(br)
            break
        for iface in ifs:
            if IXPLink.objects.filter(Q(interfaceA=iface) | Q(interfaceB=iface)).exists():
                brs.append(br)
                break

    # Get all interfaces of the BRs from above
    ifs = Interface.objects.filter(border_router__in=brs)

    # Distribute links over BRs
    br_idx = 0
    br_interfaces = 0
    for iface in ifs:
        if br_interfaces >= max_peering_per_br:
            br_interfaces = 0
            br_idx += 1
            if len(brs) <= br_idx:
                brs.append(asys.host.border_routers.create(host=asys.host))
        br_interfaces += 1
        iface.border_router = brs[br_idx]
        iface.save()

    # Delete superfluous border routers
    for br in brs[br_idx + 1:]:
        br.delete()
    if br_interfaces == 0:
        # The last BR has no interfaces left, delete it
        brs[br_idx].delete()
