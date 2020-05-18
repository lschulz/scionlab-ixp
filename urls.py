from django.urls import path

from scionlab_ixp.api import GetPeers, PeeringPoliciesAPI


app_name = 'scionlab_ixp'

urlpatterns = [
    path('host/<slug:uid>/peers', GetPeers.as_view(), name='api_get_peers'),
    path('host/<slug:uid>/policies', PeeringPoliciesAPI.as_view(), name='api_peering_policies'),
]
