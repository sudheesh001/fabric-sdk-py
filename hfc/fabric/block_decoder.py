# Copyright sudheesh.info 2018 All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import logging
import binascii
import datetime

# Import required Peer Protos
from hfc.protos.peer import chaincode_pb2
from hfc.protos.peer import chaincode_event_pb2
from hfc.protos.peer import transaction_pb2
from hfc.protos.peer import proposal_pb2
from hfc.protos.peer import proposal_response_pb2
from hfc.protos.peer import query_pb2
from hfc.protos.peer import configuration_pb2 as peer_configuration_pb2

# Import required MSP Protos
from hfc.protos.msp import msp_principal_pb2
from hfc.protos.msp import msp_config_pb2
from hfc.protos.msp import identities_pb2

# Import required Common Protos
from hfc.protos.common import common_pb2
from hfc.protos.common import configtx_pb2
from hfc.protos.common import policies_pb2
from hfc.protos.common import ledger_pb2
from hfc.protos.common import configuration_pb2 as common_configuration_pb2

# Import required Orderer Protos
from hfc.protos.orderer import configuration_pb2 as orderer_configuration_pb2
from hfc.protos.orderer import ab_pb2

# Import required Ledger Protos
from hfc.protos.ledger.rwset import rwset_pb2
from hfc.protos.ledger.rwset.kvrwset import kv_rwset_pb2


_logger = logging.getLogger(__name__ + ".block_decoder")


class BlockDecoder(object):
    """
        An object of a fully decoded protobuf message "Block"
    """

    @staticmethod
    def decode(block_bytes):
        """
        Constructs a JSON Object containing all decoded values from
        protobuf encoded `Block` bytes.

        Args:
            block_bytes (bytes): Block instance

        Returns: Dictionary containing decoded Block instance.
        """
        block = {}
        try:
            proto_block = common_pb2.Block()
            proto_block.ParseFromString(block_bytes)
            block['header'] = decode_block_header(proto_block.header)
            block['data'] = decode_block_data(proto_block.data, True)
            block['metadata'] = decode_block_metadata(proto_block.metadata)
            # Add decode for data and metadata
        except Exception as e:
            raise ValueError("BlockDecoder :: decode failed", e)
        return block

    @staticmethod
    def decode_transaction(processed_tx_bytes):
        """
        Decodes a transaction proto and constructs a deserialized object

        Args:
            processed_tx_bytes {str} -- Binary content of tx

        Returns: Dictionary containing tx block information

        Raises:
            ValueError -- If data is not passed to the method
        """
        if not processed_tx_bytes:
            raise ValueError("BlockDecoder :: decode_transaction \
                doesnot have processed transaction bytes")
        processed_tx = {}
        pr_processed_tx = transaction_pb2.ProcessedTransaction()
        pr_processed_tx.ParseFromString(processed_tx_bytes)
        if pr_processed_tx:
            processed_tx['validation_code'] = \
                pr_processed_tx.validationCode
            processed_tx['transaction_envelope'] = \
                decode_block_data_envelope(pr_processed_tx.transactionEnvelope)
        return processed_tx


type_as_string = {
    0: 'MESSAGE',  # Used for messages which are signed but opaque
    1: 'CONFIG',  # Used for messages which express the channel config
    2: 'CONFIG_UPDATE',  # Used for transactions which update the channel config
    3: 'ENDORSER_TRANSACTION',  # Used by the SDK to submit endorser based transactions
    4: 'ORDERER_TRANSACTION',  # Used internally by the orderer for management
    5: 'DELIVER_SEEK_INFO',  # Used as the type for Envelope messages submitted to instruct the Deliver API to seek
    6: 'CHAINCODE_PACKAGE'  # Used for packaging chaincode artifacts for install
}

implicit_metapolicy_rule = ['ANY', 'ALL', 'MAJORITY']

policy_policy_type = ['UNKNOWN', 'SIGNATURE', 'MSP', 'IMPLICIT_META']

implicit_metapolicy_rule = ['ANY', 'ALL', 'MAJORITY']


class HeaderType(object):
    """
        HeaderType class having decodePayload and convertToString methods
    """
    @staticmethod
    def convert_to_string(type_value):
        result = None
        try:
            result = type_as_string[type_value]
        except Exception as e:
            raise Exception("HeaderType :: convert_to_string", e)
        if not result:
            result = 'UNKNOWN_TYPE'
        return result

    @staticmethod
    def decode_payload_based_on_type(proto_data, type_value):
        result = None
        if type_value == 1:
            result = decode_config_envelope(proto_data)
        elif type_value == 2:
            result = decode_config_update_envelope(proto_data)
        elif type_value == 3:
            result = decode_endorser_transaction(proto_data)
        else:
            _logger.debug('HeaderType :: decode_payload found a header type of {} :: {}'.format(type_value, HeaderType.convert_to_string(type_value)))
            result = {}
        return result


def decode_block_header(proto_block_header):
    """
    Decodes the header of Block

    Args:
        proto_block_header (str): Block Header proto

    Returns: Decoded BlockHeader inside Block instance.
    """
    block_header = {}
    block_header['number'] = proto_block_header.number
    block_header['previous_hash'] = \
        binascii.b2a_hex(proto_block_header.previous_hash)
    block_header['data_hash'] = binascii.b2a_hex(proto_block_header.data_hash)
    return block_header


def decode_block_data(proto_block_data, not_proto=False):
    """Decodes the data of Block.

    Args:
        proto_block_data (str): Block Data proto.
        not_proto (bool): Boolean for if proto.

    Returns: deserialized block_data
    """
    data = {}
    data['data'] = []
    for i in proto_block_data.data:
        proto_envelope = None
        if not_proto:
            proto_envelope = common_pb2.Envelope()
            proto_envelope.ParseFromString(i)
        if proto_envelope:
            envelope = decode_block_data_envelope(proto_envelope)
            data['data'].append(envelope)
    return data


def decode_block_metadata(proto_block_metadata):
    """Decodes block metadata from block

    Args:
        proto_block_metadata (bytes): Block metadata proto content

    Returns: deserialized metadata contents
    """
    metadata = {}
    metadata['metadata'] = []
    if proto_block_metadata and proto_block_metadata.metadata:
        signatures = {}
        signatures = \
            decode_metadata_signatures(proto_block_metadata.metadata[0])
        metadata['metadata'].append(signatures)

        last_config = {}
        last_config = decode_last_config_sequence_number(
           proto_block_metadata.metadata[1])
        metadata['metadata'].append(last_config)

        transaction_filter = {}
        transaction_filter = \
            decode_transaction_filter(proto_block_metadata.metadata[2])
        metadata['metadata'].append(transaction_filter)

    return metadata


def decode_block_data_envelope(proto_envelope):
    """Decodes the envelope contents of Block

    Args:
        proto_envelope (str): Envelope proto

    Returns: deserialized block envelope
    """
    envelope = {}
    envelope['signature'] = proto_envelope.signature
    envelope['payload'] = {}
    proto_payload = common_pb2.Payload()
    proto_payload.ParseFromString(proto_envelope.payload)
    envelope['payload']['header'] = decode_header(proto_payload.header)
    # TODO: add envelope['payload']['data'] & ['payload']['header']
    return envelope


def decode_header(proto_header):
    """Decodes the Payload header in envelope

    Args:
        proto_header (str): Envelope Payload

    Returns: deserialized envelope header
    """
    header = {}
    header['channel_header'] = \
        decode_channel_header(proto_header.channel_header)
    header['signature_header'] = \
        decode_signature_header(proto_header.signature_header)
    return header


def decode_channel_header(header_bytes):
    """Decodes channel header for Payload channel header

    Args:
        header_bytes (str): Bytes channel header

    Return: deserialized payload channel_header
    """
    channel_header = {}
    proto_channel_header = common_pb2.ChannelHeader()
    proto_channel_header.ParseFromString(header_bytes)
    channel_header['type'] = proto_channel_header.type
    channel_header['version'] = decode_version(proto_channel_header.version)
    channel_header['timestamp'] = \
        timestamp_to_date(proto_channel_header.timestamp)
    channel_header['channel_id'] = proto_channel_header.channel_id
    channel_header['tx_id'] = proto_channel_header.tx_id
    channel_header['epoch'] = proto_channel_header.epoch
    channel_header['extension'] = proto_channel_header.extension
    return channel_header


def timestamp_to_date(timestamp):
    """Converts timestamp to current date

    Args:
        timestamp: Timestamp value

    Returns: String formatted date in %Y-%m-%d %H:%M:%S
    """
    if not timestamp:
        return None
    millis = timestamp.seconds * 1000 + timestamp.nanos / 1000000
    date = datetime.datetime.fromtimestamp(millis/1e3)
    return date.strftime("%Y-%m-%d %H:%M:%S")


def decode_version(version_long):
    """Takes version proto object and returns version

    Args:
        version_long

    Returns: integer value of version_long
    """
    return int(version_long)


def decode_signature_header(signature_header_bytes):
    """Decode signature header

    Args:
        signature_header_bytes: signature header bytes

    Returns: deserialized signature_header
    """
    signature_header = {}
    proto_signature_header = common_pb2.SignatureHeader()
    proto_signature_header.ParseFromString(signature_header_bytes)
    signature_header['creator'] = \
        decode_identity(proto_signature_header.creator)
    signature_header['nonce'] = \
        binascii.b2a_hex(proto_signature_header.nonce)
    return signature_header


def decode_identity(id_bytes):
    """Decodes identity

    Args:
        id_bytes: byte of identity

    Returns: deserialized identity
    """
    identity = {}
    try:
        proto_identity = identities_pb2.SerializedIdentity()
        proto_identity.ParseFromString(id_bytes)
        identity['mspid'] = proto_identity.mspid
        identity['id_bytes'] = proto_identity.id_bytes
    except Exception as e:
        raise ValueError("BlockDecoder :: decode_identiy failed", e)
    return identity


def decode_metadata_signatures(metadata_bytes):
    """Decodes metadata signature from bytes

    Args:
        metadata_bytes (str): Metadata object proto

    Returns: deserialized Metadata blocks
    """
    metadata = {}
    proto_metadata = common_pb2.Metadata()
    proto_metadata.ParseFromString(metadata_bytes)
    metadata['value'] = proto_metadata.value
    metadata['signatures'] = \
        decode_metadata_value_signatures(proto_metadata.signatures)
    return metadata


def decode_metadata_value_signatures(proto_meta_signatures):
    """Decodes all signatures in metadata values

    Args:
        proto_meta_signatures (list(str)): List of value objects

    Returns: deserialized list of signatures from metadata values
    """
    signatures = []
    if proto_meta_signatures:
        for signature in proto_meta_signatures:
            metadata_signature = {}
            metadata_signature['signature_header'] = \
                decode_signature_header(signature.signature_header)
            metadata_signature['signature'] = signature.signature
            signatures.append(metadata_signature)
    return signatures


def decode_last_config_sequence_number(metadata_bytes):
    """Decodes last configuration and index for sequence number

    Args:
        metadata_bytes (str): encoded content for sequence number

    Returns: deserialized dictionary of config sequence number
    """
    last_config = {}
    last_config['value'] = {}
    if metadata_bytes:
        proto_metadata = common_pb2.Metadata()
        proto_metadata.ParseFromString(metadata_bytes)
        proto_last_config = common_pb2.LastConfig()
        proto_last_config.ParseFromString(proto_metadata.value)
        last_config['value']['index'] = proto_last_config.index
        last_config['signatures'] = \
            decode_metadata_value_signatures(proto_metadata.signatures)
    return last_config


def decode_transaction_filter(metadata_bytes):
    """Decodes transaction filter from metadata bytes

    Args:
        metadata_bytes (str): Encoded list of transaction filters

    Returns: decoded transaction_filter list
    """
    transaction_filter = []
    if not metadata_bytes:
        return None

    for i in metadata_bytes:
        transaction_filter.append(int(i))
    return transaction_filter


def decode_endorser_transaction(trans_bytes):
    """Decodes

    Args:
        trans_bytes {[type]}: Serialized endorser transaction bytes

    Returns: deserialized dictionary of endorser transaction data
    """
    data = {}
    if trans_bytes:
        transaction = transaction_pb2.Transaction()
        transaction.ParseFromString(trans_bytes)
        data['actions'] = []
        if transaction and transaction.actions:
            for tx_action in transaction.actions:
                action = {}
                action['header'] = decode_signature_header(tx_action.header)
                action['payload'] = decode_chaincode_action_payload(tx_action.payload)
                data['actions'].append(action)
    return data


def decode_config_envelope(config_envelope_bytes):
    """Decodes configuration envelope

    Args:
        config_envelope_bytes: byte of config envelope

    Returns: deserialized config envelope
    """
    config_envelope = {}
    proto_config_envelope = configtx_pb2.ConfigEnvelope()
    proto_config_envelope.ParseFromString(config_envelope_bytes)
    config_envelope['config'] = decode_config(proto_config_envelope.config)
    config_envelope['last_update'] = {}
    proto_last_update = proto_config_envelope.last_update
    if proto_last_update:
        config_envelope['last_update']['payload'] = {}
        proto_payload = common_pb2.Payload()
        proto_payload.ParseFromString(proto_last_update.payload)
        config_envelope['last_update']['payload']['header'] = decode_header(proto_payload.header)
        config_envelope['last_update']['payload']['data'] = decode_config_update_envelope(proto_payload.data)
        config_envelope['last_update']['signature'] = proto_last_update.signature
    return config_envelope


def decode_config(proto_config):
    """Decodes configuration from config envelope
    
    Args:
        proto_config (bytes): Config value

    Returns: deserialized config
    """
    config = {}
    config['sequence'] = str(proto_config.sequence)
    config['channel_group'] = decode_config_group(proto_config.channel_group)
    # config['type'] = proto_config.type
    # TODO: getType() equivalent
    return config


def decode_config_update_envelope(config_update_envelope_bytes):
    """Decode config update envelope
    
    Args:
        config_update_envelope_bytes (str): Bytes of update envelope

    Returns: deserialized config update envelope signatures
    """
    config_update_envelope = {}
    proto_config_update_envelope = configtx_pb2.ConfigUpdateEnvelope()
    proto_config_update_envelope.ParseFromString(config_update_envelope_bytes)
    config_update_envelope['config_update'] = decode_config_update(proto_config_update_envelope.config_update)
    signatures = []
    for signature in proto_config_update_envelope.signatures:
        proto_config_signature = signature
        config_signature = decode_config_signature(proto_config_signature)
        signatures.push(config_signature)
    config_update_envelope['signatures'] = signatures
    return config_update_envelope


def decode_config_update(config_update_bytes):
    """Decodes update bytes in configuration
    
    Args:
        config_update_bytes (str): Bytes
 
    Returns: deserialized configuration update
    """
    config_update = {}
    proto_config_update = configtx_pb2.ConfigUpdate()
    proto_config_envelope.ParseFromString(config_update_bytes)
    config_update['channel_id'] = proto_config_update.channel_id
    config_update['read_set'] = decode_config_group(proto_config_update.read_set)
    config_update['write_set'] = decode_config_group(proto_config_update.write_set)
    # config_update['type'] = proto_config_update TODO: getType() equivalent
    return config_update


def decode_config_groups(config_group_map):
    """Decodes configuration groups inside ConfigGroup
    
    Args:
        config_group_map (str): Serialized ConfigGroup.groups object

    Returns: map of configuration groups.
    """
    config_groups = {}
    # keys =
    # TODO: Fill in the rest
    return config_groups


def decode_config_group(proto_config_group):
    """Decodes configuration group from config protos
    
    Args:
        proto_config_group (str): serialized ConfigGroup() object

    Returns: deserialized config_groups dictionary
    """

    if not proto_config_group:
        return None
    config_group = {}
    config_group['version'] = decode_version(proto_config_group.version)
    config_group['groups'] = decode_config_groups(proto_config_group.groups)
    config_group['values'] = decode_config_values(proto_config_group.values)
    config_group['policies'] = decode_config_policies(proto_config_group.policies)
    config_group['mod_policy'] = proto_config_group.mod_policy
    return config_group


def decode_config_values(config_value_map):
    """Decodes configuration values inside each configuration key

    Args:
        config_value_map (str): Serialized values map for each config key

    Returns: map of configuration values for each key
    """
    config_values = {}
    # keys =
    # TODO: Fill in the rest
    return config_values


def decode_config_value(proto_config_value):
    """Decodes

    Args:
        trans_bytes {[type]} -- [description]
    """
    config_value_key = proto_config_value.key
    config_value = {}
    config_value['version'] = decode_version(proto_config_value.value.version)
    config_value['mod_policy'] = proto_config_value.value.mod_policy
    config_value['value'] = {}
    if config_value_key == 'AnchorPeers':
        pass
    elif config_value_key == 'MSP':
        pass
    elif config_value_key == 'ConsensusType':
        pass
    elif config_value_key == 'BatchSize':
        pass
    elif config_value_key == 'BatchTimeout':
        pass
    elif config_value_key == 'ChannelRestrictions':
        pass
    elif config_value_key == 'CreationPolicy':
        pass
    elif config_value_key == 'Consortium':
        pass
    elif config_value_key == 'ChainCreationPolicyNames':
        pass
    elif config_value_key == 'HashingAlgorithm':
        pass
    elif config_value_key == 'BlockDataHashingStructure':
        pass
    elif config_value_key == 'OrdererAddresses':
        pass
    else:
        pass
    return config_value


def decode_config_policies(config_policy_map):
    """Decodes list of configuration policies

    Args:
        config_policy_map (str): Serialized list of configuration policies

    Returns: deserialized map of config policies.
    """
    config_policies = {}
    # keys =
    return config_policies


def decode_config_policy(proto_config_policy):
    """Decodes

    Args:
        trans_bytes {[type]} -- [description]
    """
    pass


def decode_implicit_meta_policy(implicit_meta_policy_bytes):
    """Decodes

    Args:
        trans_bytes {[type]} -- [description]
    """
    pass


def decode_signature_policy_envelope(signature_policy_envelope_bytes):
    """Decodes

    Args:
        trans_bytes {[type]} -- [description]
    """
    pass


def decode_signature_policy(proto_signature_policy):
    """Decodes

    Args:
        trans_bytes {[type]} -- [description]
    """
    pass


def decode_MSP_principal(proto_msp_principal):
    """Decodes

    Args:
        trans_bytes {[type]} -- [description]
    """
    pass


def decode_config_signature(proto_configSignature):
    """Decodes

    Args:
        trans_bytes {[type]} -- [description]
    """
    pass


def decode_fabric_MSP_config(msp_config_bytes):
    """Decodes

    Args:
        trans_bytes {[type]} -- [description]
    """
    pass


def decode_fabric_OU_identifier(proto_organizational_unit_identitfiers):
    """Decodes

    Args:
        trans_bytes {[type]} -- [description]
    """
    pass


def to_PEM_certs(buffer_array_in):
    """Decodes

    Args:
        trans_bytes {[type]} -- [description]
    """
    pass


def decode_signing_identity_info(signing_identity_info_bytes):
    """Decodes

    Args:
        trans_bytes {[type]} -- [description]
    """
    pass


def decode_key_info(key_info_bytes):
    """Decodes

    Args:
        trans_bytes {[type]} -- [description]
    """
    pass


def decode_chaincode_action_payload(payload_bytes):
    """Decodes

    Args:
        trans_bytes {[type]} -- [description]
    """
    pass


def decode_chaincode_proposal_payload(chaincode_proposal_payload_bytes):
    """Decodes

    Args:
        trans_bytes {[type]} -- [description]
    """
    pass


def decode_chaincode_endorsed_action(proto_chaincode_endorsed_action):
    """Decodes

    Args:
        trans_bytes {[type]} -- [description]
    """
    pass


def decode_endorsement(proto_endorsement):
    """Decodes

    Args:
        trans_bytes {[type]} -- [description]
    """
    pass


def decode_proposal_response_payload(proposal_response_payload_bytes):
    """Decodes

    Args:
        trans_bytes {[type]} -- [description]
    """
    pass


def decode_chaincode_action(action_bytes):
    """Decodes

    Args:
        trans_bytes {[type]} -- [description]
    """
    pass


def decode_chaincode_events(event_bytes):
    """Decodes

    Args:
        trans_bytes {[type]} -- [description]
    """
    pass


def decode_chaincode_id(proto_chaincode_id):
    """Decodes

    Args:
        trans_bytes {[type]} -- [description]
    """
    pass


def decode_readwrite_sets(rw_sets_bytes):
    """Decodes

    Args:
        trans_bytes {[type]} -- [description]
    """
    pass


def decode_kv_rw_set(kv_bytes):
    """Decodes

    Args:
        trans_bytes {[type]} -- [description]
    """
    pass


def decode_kv_read(proto_kv_read):
    """Decodes

    Args:
        trans_bytes {[type]} -- [description]
    """
    pass


def decode_range_query_info(proto_range_query_info):
    """Decodes
    
    Args:
        proto_range_query_info {[type]} -- [description]
    """
    pass


def decode_kv_write(proto_kv_write):
    """Decodes
    
    Args:
        proto_range_query_info {[type]} -- [description]
    """
    pass


def decode_response(proto_response):
    """Decodes
    
    Args:
        proto_range_query_info {[type]} -- [description]
    """
    pass
