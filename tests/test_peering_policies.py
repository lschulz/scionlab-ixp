from django.test import TestCase

from scionlab.models.core import ISD
from scionlab.models.user_as import UserAS

from scionlab_ixp.models import ASPeerPolicy, ISDPeerPolicy, IXP, IXPLink, IXPMember
from scionlab_ixp.peering_policy import apply_peering_policy


class PeeringPoliciesTest(TestCase):
    fixtures = ['testdata']

    def setUp(self):
        # Create IXPs
        self.ixp1 = IXP.objects.create(label="ixp1", ip_network="10.1.1.0/24")
        self.ixp2 = IXP.objects.create(label="ixp2", ip_network="10.1.2.0/24")

        # Set user ASes as IXP members
        self.ases = [UserAS.objects.get(as_id="ffaa:1:%d" % i) for i in range(1, 6)]
        IXPMember.objects.create(ixp=self.ixp1, host=self.ases[0].hosts.first(), public_ip="10.1.1.2")
        IXPMember.objects.create(ixp=self.ixp1, host=self.ases[1].hosts.first(), public_ip="10.1.1.3")
        IXPMember.objects.create(ixp=self.ixp1, host=self.ases[2].hosts.first(), public_ip="10.1.1.4")
        IXPMember.objects.create(ixp=self.ixp1, host=self.ases[3].hosts.first(), public_ip="10.1.1.5")
        IXPMember.objects.create(ixp=self.ixp1, host=self.ases[4].hosts.first(), public_ip="10.1.1.6")

        IXPMember.objects.create(ixp=self.ixp2, host=self.ases[0].hosts.first(), public_ip="10.1.2.2")
        IXPMember.objects.create(ixp=self.ixp2, host=self.ases[1].hosts.first(), public_ip="10.1.2.3")
        IXPMember.objects.create(ixp=self.ixp2, host=self.ases[2].hosts.first(), public_ip="10.1.2.4")

    def test_as_policies(self):
        """Test AS peering policies."""
        # Allow 17-ffaa:1:1 -> 19-ffaa:1:2
        allow_0_to_1 = self._add_as_policy(self.ixp1, self.ases[0], self.ases[1], False)
        self.assertEqual(IXPLink.objects.count(), 0)

        # Deny 17-ffaa:1:1 -> 20-ffaa:1:3
        self._add_as_policy(self.ixp1, self.ases[0], self.ases[2], True)
        self.assertEqual(IXPLink.objects.count(), 0)

        # Allow 19-ffaa:1:2 -> 17-ffaa:1:1
        self._add_as_policy(self.ixp1, self.ases[1], self.ases[0], False)
        self.assertEqual(IXPLink.objects.count(), 1)
        self.assertTrue(self._link_exists(self.ixp1, self.ases[0], self.ases[1]))

        # Allow 20-ffaa:1:3 -> 17-ffaa:1:1
        self._add_as_policy(self.ixp1, self.ases[2], self.ases[0], False)
        self.assertEqual(IXPLink.objects.count(), 1)
        self.assertTrue(self._link_exists(self.ixp1, self.ases[0], self.ases[1]))

        # Remove (Allow 17-ffaa:1:1 -> 19-ffaa:1:2)
        self._delete_policy(allow_0_to_1)
        self.assertEqual(IXPLink.objects.count(), 0)

    def test_isd_policies(self):
        """Test ISD peering policies and their interaction with AS policies."""
        isd17 = ISD.objects.get(isd_id=17)
        isd19 = ISD.objects.get(isd_id=19)

        # Allow 17-ffaa:1:1 -> ISD 17
        allow_1_to_isd17 = self._add_isd_policy(self.ixp1, self.ases[0], isd17, False)
        self.assertEqual(IXPLink.objects.count(), 0)

        # Allow 17-ffaa:1:5 -> ISD 17
        self._add_isd_policy(self.ixp1, self.ases[4], isd17, False)
        self.assertEqual(IXPLink.objects.count(), 1)
        self.assertTrue(self._link_exists(self.ixp1, self.ases[0], self.ases[4]))

        # Allow 19-ffaa:1:2 -> ISD 17
        self._add_isd_policy(self.ixp1, self.ases[1], isd17, False)
        self.assertEqual(IXPLink.objects.count(), 1)
        self.assertTrue(self._link_exists(self.ixp1, self.ases[0], self.ases[4]))

        # Allow 17-ffaa:1:1 -> ISD 19
        self._add_isd_policy(self.ixp1, self.ases[0], isd19, False)
        self.assertEqual(IXPLink.objects.count(), 2)
        self.assertTrue(self._link_exists(self.ixp1, self.ases[0], self.ases[4]))
        self.assertTrue(self._link_exists(self.ixp1, self.ases[0], self.ases[1]))

        # Allow 17-ffaa:1:5 -> ISD 19
        self._add_isd_policy(self.ixp1, self.ases[4], isd19, False)
        self.assertEqual(IXPLink.objects.count(), 3)
        self.assertTrue(self._link_exists(self.ixp1, self.ases[0], self.ases[4]))
        self.assertTrue(self._link_exists(self.ixp1, self.ases[0], self.ases[1]))
        self.assertTrue(self._link_exists(self.ixp1, self.ases[4], self.ases[1]))

        # Deny 17-ffaa:1:5 -> 19-ffaa:1:2 (AS deny has precedence over ISD allow)
        self._add_as_policy(self.ixp1, self.ases[4], self.ases[1], True)
        self.assertEqual(IXPLink.objects.count(), 2)
        self.assertTrue(self._link_exists(self.ixp1, self.ases[0], self.ases[4]))
        self.assertTrue(self._link_exists(self.ixp1, self.ases[0], self.ases[1]))

        # Remove (Allow 17-ffaa:1:1 -> ISD 17)
        self._delete_policy(allow_1_to_isd17)
        self.assertEqual(IXPLink.objects.count(), 1)
        self.assertTrue(self._link_exists(self.ixp1, self.ases[0], self.ases[1]))

        # Deny 17-ffaa:1:1 -> ISD 17
        self._add_isd_policy(self.ixp1, self.ases[0], isd17, True)
        self.assertEqual(IXPLink.objects.count(), 1)
        self.assertTrue(self._link_exists(self.ixp1, self.ases[0], self.ases[1]))

        # Allow 17-ffaa:1:1 -> 17-ffaa:1:5 (AS allow has precedence over ISD deny)
        self._add_as_policy(self.ixp1, self.ases[0], self.ases[4], False)
        self.assertEqual(IXPLink.objects.count(), 2)
        self.assertTrue(self._link_exists(self.ixp1, self.ases[0], self.ases[1]))
        self.assertTrue(self._link_exists(self.ixp1, self.ases[0], self.ases[4]))

    def _add_as_policy(self, ixp, asys, peer_as, deny):
        """Add an AS peering policy and apply it.

        :returns: The newly created policy instance.
        """
        policy = ASPeerPolicy.objects.create(ixp=ixp, AS=asys, peer_as=peer_as, deny=deny)

        apply_peering_policy(asys, self.ixp1)
        apply_peering_policy(asys, self.ixp2)

        return policy

    def _add_isd_policy(self, ixp, asys, peer_isd, deny):
        """Add an ISD peering policy and apply it.

        :returns: The newly created policy instance.
        """
        policy = ISDPeerPolicy.objects.create(ixp=ixp, AS=asys, peer_isd=peer_isd, deny=deny)

        apply_peering_policy(asys, self.ixp1)
        apply_peering_policy(asys, self.ixp2)

        return policy

    def _delete_policy(self, policy):
        """Delete a peering policy and apply the changes."""
        policy.delete()

        apply_peering_policy(policy.AS, self.ixp1)
        apply_peering_policy(policy.AS, self.ixp2)

    def _link_exists(self, ixp, asA, asB):
        """Check whether an IXP link over the given IXP exists between `asA` and `asB`.

        :returns: True, if a link exists, False if not.
        """
        count1 = IXPLink.objects.filter(ixp=ixp, interfaceA__AS=asA, interfaceB__AS=asB).count()
        count2 = IXPLink.objects.filter(ixp=ixp, interfaceA__AS=asB, interfaceB__AS=asA).count()

        # Should never have multiple links between the same two ASes.
        self.assertFalse(count1 > 2 or count2 > 2)
        self.assertFalse(count1 > 1 and count2 > 1)

        return (count1 + count2) > 0
