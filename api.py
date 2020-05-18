import json
import jsonschema

import django.db
import django.core.exceptions
from django.views import View
from django.views.generic.detail import SingleObjectMixin
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.http import (
    HttpResponse,
    HttpResponseBadRequest,
    JsonResponse
)

from scionlab.models.core import Host, ISD
from scionlab.models.user_as import UserAS
from scionlab.views.api import _basicauth_host

from scionlab_ixp.models import IXP, IXPLink, IXPMember, ASPeerPolicy, ISDPeerPolicy
from scionlab_ixp.peering_policy import apply_peering_policy


@method_decorator(_basicauth_host, name='dispatch')
class GetPeers(SingleObjectMixin, View):
    """Get the list of peers currently connected to an AS.

    GET Parameters:
    `ixp` (optional): Id (primary key) of the IXP to query. If not specified all IXPs are included
                      in the response.

    Response:
    A JSON encoded dictionary mapping IXPs to lists of peers. Peers are encoded as dictionaries
    containing the AS-ID and AS label.

    The request is authenticated via a per-Host secret field, included in the request parameters.
    """
    model = Host
    slug_field = 'uid'
    slug_url_kwarg = 'uid'

    def get(self, request, *args, **kwargs):
        as_id = self.get_object().AS_id
        response = {}

        try:
            ixp_id = _get_ixp_param(request.GET)
        except ValueError:
            return HttpResponseBadRequest()

        if ixp_id is not None:
            # Get peers at the requested IXP.
            response[ixp_id] = _get_peers(as_id, ixp_id)
        else:
            # Get peers at all IXPs.
            for ixp_id in IXPMember.objects.filter(host__AS_id=as_id).values_list('ixp_id', flat=True):
                response[ixp_id] = _get_peers(as_id, ixp_id)

        return JsonResponse(response)


_policy_api_schema = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "definitions": {
        "AsId": {
            "type": "string",
            "pattern": "^([0-9a-fA-F]{1,4}):([0-9a-fA-F]{1,4}):([0-9a-fA-F]{1,4})$"
        },
        "AsList": {
            "type": "array",
            "uniqueItems": True,
            "items": {
                "$ref": "#/definitions/AsId"
            }
        },
        "IsdList": {
            "type": "array",
            "uniqueItems": True,
            "items": {
                "type": "number"
            }
        }
    },
    "type": "object",
    "additionalProperties": False,
    "patternProperties": {
        "^[0-9]+$": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "AS": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties":
                    {
                        "accept": {
                            "$ref": "#/definitions/AsList"
                        },
                        "deny": {
                            "$ref": "#/definitions/AsList"
                        }
                    }
                },
                "ISD": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "accept": {
                            "$ref": "#/definitions/IsdList"
                        },
                        "deny": {
                            "$ref": "#/definitions/IsdList"
                        }
                    }
                }
            }
        }
    }
}

_policy_json_validator = jsonschema.Draft7Validator(_policy_api_schema)


class InvalidPolicy(Exception):
    """Raised when policy validation fails for any reason."""
    pass


@method_decorator(csrf_exempt, name='dispatch')
@method_decorator(_basicauth_host, name='dispatch')
class PeeringPoliciesAPI(SingleObjectMixin, View):
    """Get, create, or delete peering policies.

    The request is authenticated via a per-Host secret field, included in the request parameters.
    """
    model = Host
    slug_field = 'uid'
    slug_url_kwarg = 'uid'

    def get(self, request, *args, **kwargs):
        """Get all peering policies of an AS.

        GET Parameters:
        `ixp` (optional): Id (primary key) of the IXP to query. If not specified all IXPs are
                          included in the response.

        Response:
        A JSON encoded dictionary mapping IXPs to lists of peers. Peers are encoded as dictionaries
        containing the AS-ID and AS label.
        """
        as_id = self.get_object().AS_id
        response = {}

        try:
            ixp_id = _get_ixp_param(request.GET)
        except ValueError:
            return HttpResponseBadRequest()

        if ixp_id is not None:
            # Get policies for the requested IXP.
            response[ixp_id] = _get_policies(as_id, ixp_id)
        else:
            # Get policies for all IXPs.
            for ixp_id in IXPMember.objects.filter(host__AS_id=as_id).values_list('ixp_id', flat=True):
                response[ixp_id] = _get_policies(as_id, ixp_id)

        return JsonResponse(response)

    def post(self, request, *args, **kwargs):
        """Create new AS and ISD peering policies.

        The request body should contain JSON formatted polices in the same format returned for GET
        request. The request fails if any of the given policies are invalid or contradict existing
        policies.
        """
        asys = self.get_object().AS.useras

        try:
            parsed_request = json.loads(request.body.decode('utf-8'))
        except json.JSONDecodeError:
            return HttpResponseBadRequest()
        if not _policy_json_validator.is_valid(parsed_request):
            return HttpResponseBadRequest()

        try:
            _create_policies(asys, parsed_request)
        except InvalidPolicy as e:
            return HttpResponseBadRequest(str(e), content_type="text/plain")

        return HttpResponse(status=201) # 201 Created

    def delete(self, request, *args, **kwargs):
        """Delete AS and ISD policies.

        The request body should contain JSON formatted polices in the same format returned for GET
        request.
        """
        asys = self.get_object().AS.useras

        try:
            parsed_request = json.loads(request.body.decode('utf-8'))
        except json.JSONDecodeError:
            return HttpResponseBadRequest()
        if not _policy_json_validator.is_valid(parsed_request):
            return HttpResponseBadRequest()

        try:
            _delete_policies(asys, parsed_request)
        except InvalidPolicy as e:
            return HttpResponseBadRequest(str(e), content_type="text/plain")

        return HttpResponse(status=204) # 204 No Content


def _get_ixp_param(request_params):
    """Get the "ixp" request parameter and parse it to an integer.

    :returns: None, if no "ixp" is given, or an integer.
    :raises ValueError: The "ixp" parameter is not a valid integer.
    """
    raw = request_params.get('ixp')
    if raw is not None:
        return int(raw)
    else:
        return raw


def _get_peers(as_id, ixp_id):
    """Get all current peers of AS `as_id` at IXP `ixp_id`.

    :param as_id: AS primary key.
    :param ixp_id: IXP primary key.
    :returns: A list of dictionaries describing the peer ASes.
    """
    links = IXPLink.objects.filter(ixp_id=ixp_id, interfaceA__AS_id=as_id)
    values = list(links.values_list('interfaceB__AS__as_id', 'interfaceB__AS__label'))

    links = IXPLink.objects.filter(ixp_id=ixp_id, interfaceB__AS_id=as_id)
    values.extend(list(links.values_list('interfaceA__AS__as_id', 'interfaceA__AS__label')))

    return [{'as_id': as_id, 'label': label} for as_id, label in values]


def _get_policies(as_id, ixp_id):
    """Get all peering policies of AS `as_id` at IXP `ixp_id`.

    :param as_id: AS primary key.
    :param ixp_id: IXP primary key.
    :returns: Nested dictionaries containing all AS and ISD policies.
    """
    policies = {'AS': {}, 'ISD': {}}

    # AS policies
    query = ASPeerPolicy.objects.filter(AS_id=as_id, ixp_id=ixp_id, deny=False)
    policies['AS']['accept'] = list(query.values_list('peer_as__as_id', flat=True))

    query = ASPeerPolicy.objects.filter(AS_id=as_id, ixp_id=ixp_id, deny=True)
    policies['AS']['deny'] = list(query.values_list('peer_as__as_id', flat=True))

    # ISD policies
    query = ISDPeerPolicy.objects.filter(AS_id=as_id, ixp_id=ixp_id, deny=False)
    policies['ISD']['accept'] = list(query.values_list('peer_isd__isd_id', flat=True))

    query = ISDPeerPolicy.objects.filter(AS_id=as_id, ixp_id=ixp_id, deny=True)
    policies['ISD']['deny'] = list(query.values_list('peer_isd__isd_id', flat=True))

    return policies


@django.db.transaction.atomic
def _create_policies(asys: UserAS, parsed_request):
    """Create the peering policies contained in `parsed_request` and apply them.

    If creating any policy fails or parsed_request is invalid, the whole process is rolled back.

    :param asys: AS model instance of the AS the policies belong to.
    :param parsed_request: Nested dictionary in the same format _get_policies() returns.

    :raises InvalidPolicy: The request contains invalid policies.
    """
    for ixp_id, policies in parsed_request.items():
        try:
            ixp = IXP.objects.get(id=ixp_id)
        except IXP.DoesNotExist:
            raise InvalidPolicy("IXP %s does not exist." % ixp_id)

        if 'AS' in policies:
            for peer_as in policies['AS'].get('accept', []):
                _create_as_policy(ixp, asys, peer_as, deny=False)
            for peer_as in policies['AS'].get('deny', []):
                _create_as_policy(ixp, asys, peer_as, deny=True)

        if 'ISD' in policies:
            for peer_isd in policies['ISD'].get('accept', []):
                _create_isd_policy(ixp, asys, peer_isd, deny=False)
            for peer_isd in policies['ISD'].get('deny', []):
                _create_isd_policy(ixp, asys, peer_isd, deny=True)

        apply_peering_policy(asys, ixp)


def _create_as_policy(ixp: IXP, asys: UserAS, peer_as: UserAS, deny: bool):
    """Create a new AS policy.

    :raises InvalidPolicy:
    """
    try:
        peer_id = UserAS.objects.filter(as_id=peer_as).values_list('id', flat=True).get()
    except UserAS.DoesNotExist:
        raise InvalidPolicy("User AS %s does not exist." % peer_as)

    try:
        ASPeerPolicy.objects.create(ixp=ixp, AS=asys, peer_as_id=peer_id, deny=deny)
    except django.core.exceptions.ValidationError as e:
        raise InvalidPolicy(e)
    except django.db.IntegrityError:
        raise InvalidPolicy("Invalid or duplicate policy.")


def _create_isd_policy(ixp: IXP, asys: UserAS, peer_isd: ISD, deny: bool):
    """Create a new ISD policy.

    :raises InvalidPolicy:
    """
    try:
        peer_id = ISD.objects.filter(isd_id=peer_isd).values_list('id', flat=True).get()
    except ISD.DoesNotExist:
        raise InvalidPolicy("ISD %d does not exist." % peer_isd)

    try:
        ISDPeerPolicy.objects.create(ixp=ixp, AS=asys, peer_isd_id=peer_id, deny=deny)
    except django.core.exceptions.ValidationError as e:
        raise InvalidPolicy(e)
    except django.db.IntegrityError:
        raise InvalidPolicy("Invalid or duplicate policy.")


@django.db.transaction.atomic
def _delete_policies(asys: UserAS, parsed_request):
    """Delete the peering policies contained in `parsed_request` and apply the remaining policies.

    If deleting any policy fails or parsed_request is invalid, the whole process is rolled back.

    :param asys: AS model instance of the AS the policies belong to.
    :param parsed_request: Nested dictionary in the same format _get_policies() returns.

    :raises django.db.DatabaseError:
    """
    for ixp_id, policies in parsed_request.items():
        try:
            ixp = IXP.objects.get(id=ixp_id)
        except IXP.DoesNotExist:
            raise InvalidPolicy("IXP %s does not exist." % ixp_id)

        if 'AS' in policies:
            for peer_as in policies['AS'].get('accept', []):
                _delete_as_policy(ixp, asys, peer_as, deny=False)
            for peer_as in policies['AS'].get('deny', []):
                _delete_as_policy(ixp, asys, peer_as, deny=True)

        if 'ISD' in policies:
            for peer_isd in policies['ISD'].get('accept', []):
                _delete_isd_policy(ixp, asys, peer_isd, deny=False)
            for peer_isd in policies['ISD'].get('deny', []):
                _delete_isd_policy(ixp, asys, peer_isd, deny=True)

        apply_peering_policy(asys, ixp)


def _delete_as_policy(ixp: IXP, asys: UserAS, peer_as: UserAS, deny: bool):
    """Delete an AS policy. Does not fail if the policy does not exist.

    :raises InvalidPolicy:
    """
    try:
        peer_id = UserAS.objects.filter(as_id=peer_as).values_list('id', flat=True).get()
    except UserAS.DoesNotExist:
        raise InvalidPolicy("User AS %s does not exist." % peer_as)

    ASPeerPolicy.objects.filter(ixp=ixp, AS=asys, peer_as_id=peer_id, deny=deny).delete()


def _delete_isd_policy(ixp: IXP, asys: UserAS, peer_isd: ISD, deny: bool):
    """Delete an ISD policy. Does not fail if the policy does not exist.

    :raises InvalidPolicy:
    """
    try:
        peer_id = ISD.objects.filter(isd_id=peer_isd).values_list('id', flat=True).get()
    except ISD.DoesNotExist:
        raise InvalidPolicy("ISD %d does not exist." % peer_isd)

    ISDPeerPolicy.objects.filter(ixp=ixp, AS=asys, peer_isd_id=peer_id, deny=deny).delete()
