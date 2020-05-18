from django.test import TestCase

from scionlab.models.core import Host
from scionlab.models.user_as import UserAS
from scionlab.tests.utils import basic_auth

from scionlab_ixp.models import ASPeerPolicy, IXP, IXPMember
from scionlab_ixp.peering_policy import apply_peering_policy


class PeeringApiTests(TestCase):
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

        # Avoid duplication, get this info here:
        self.host = Host.objects.get(AS__as_id="ffaa:1:1")
        self.url_peers = '/api/peering/host/%s/peers' % self.host.uid
        self.url_policies = '/api/peering/host/%s/policies' % self.host.uid
        self.auth_headers = basic_auth(self.host.uid, self.host.secret)

    def test_get_peers(self):
        """Test retrieveing a list of peers."""
        # No peering links yet
        resp = self.client.get(self.url_peers, **self.auth_headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"1": [], "2": []})

        # Invalid GET parameter
        resp = self.client.get(self.url_peers, {'ixp': 'nan'}, **self.auth_headers)
        self.assertEqual(resp.status_code, 400)

        # Allow 17-ffaa:1:1 -> 19-ffaa:1:2 and 19-ffaa:1:2 -> 17-ffaa:1:1
        ASPeerPolicy.objects.create(ixp=self.ixp1, AS=self.ases[0], peer_as=self.ases[1], deny=False)
        ASPeerPolicy.objects.create(ixp=self.ixp1, AS=self.ases[1], peer_as=self.ases[0], deny=False)
        apply_peering_policy(self.ases[0], self.ixp1)
        apply_peering_policy(self.ases[1], self.ixp1)

        resp = self.client.get(self.url_peers, **self.auth_headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"1": [{"as_id": "ffaa:1:2", "label": ""}], "2": []})

        resp = self.client.get(self.url_peers, {'ixp': '1'}, **self.auth_headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"1": [{"as_id": "ffaa:1:2", "label": ""}]})

        resp = self.client.get(self.url_peers, {'ixp': '2'}, **self.auth_headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"2": []})

    def test_policy_api(self):
        """Test the API get, create, and delete policy API."""
        # No policies yet
        data = {
            "1": {
                "AS": {"accept": [], "deny": []},
                "ISD": {"accept": [], "deny": []}},
            "2": {
                "AS": {"accept": [], "deny": []},
                "ISD": {"accept": [], "deny": []}}
        }
        resp = self.client.get(self.url_policies, **self.auth_headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), data)

        # Invalid request format
        data = {"1": {"accept": []}}
        resp = self.client.post(self.url_policies, data, content_type="application/json", **self.auth_headers)
        self.assertEqual(resp.status_code, 400)

        # Add some policies
        data = {
            "1": {
                "AS": {"accept": ["ffaa:1:4"], "deny": ["ffaa:1:5"]},
                "ISD": {"accept": [19], "deny": [20]}},
            "2": {
                "AS": {"accept": ["ffaa:1:2"]}}
        }
        resp = self.client.post(self.url_policies, data, content_type="application/json", **self.auth_headers)
        self.assertEqual(resp.status_code, 201)

        # Try adding an invalid policy
        data = {"1": {"AS": {"accept": ["ffaa:1:1"]}}} # can't accept peering with oneself
        resp = self.client.post(self.url_policies, data, content_type="application/json", **self.auth_headers)
        self.assertEqual(resp.status_code, 400)

        # Try adding an already existing policy
        data = {"1": {"AS": {"accept": ["ffaa:1:2", "ffaa:1:3", "ffaa:1:4"]}}} # accept ffaa:1:4 is already set
        resp = self.client.post(self.url_policies, data, content_type="application/json", **self.auth_headers)
        self.assertEqual(resp.status_code, 400)

        # Try adding a contradictory policy
        data = {"1": {"AS": {"accept": ["ffaa:1:5"]}}} # contradicts accept: "ffaa:1:5"
        resp = self.client.post(self.url_policies, data, content_type="application/json", **self.auth_headers)
        self.assertEqual(resp.status_code, 400)

        # Check whether the valid policies are there
        data = {
            "1": {
                "AS": {"accept": ["ffaa:1:4"], "deny": ["ffaa:1:5"]},
                "ISD": {"accept": [19], "deny": [20]}},
            "2": {
                "AS": {"accept": ["ffaa:1:2"], "deny": []},
                "ISD": {"accept": [], "deny": []}}
        }
        resp = self.client.get(self.url_policies, **self.auth_headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), data)

        # Filter for IXP 2
        resp = self.client.get(self.url_policies, {"ixp": "2"}, **self.auth_headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"2": data["2"]})

        # Delete some policy
        data = {"1": {"ISD": {"deny": [20]}}}
        resp = self.client.delete(self.url_policies, data, content_type="application/json", **self.auth_headers)
        self.assertEqual(resp.status_code, 204)

        # Check whether the policies have been modified as expected
        data = {
            "1": {
                "AS": {"accept": ["ffaa:1:4"], "deny": ["ffaa:1:5"]},
                "ISD": {"accept": [19], "deny": []}},
            "2": {
                "AS": {"accept": ["ffaa:1:2"], "deny": []},
                "ISD": {"accept": [], "deny": []}}
        }
        resp = self.client.get(self.url_policies, **self.auth_headers)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), data)
