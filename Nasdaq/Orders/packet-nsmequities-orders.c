/* packet-nsmequities-orders.c
 * Routines for Nasdaq Ouch Orders dissection
 *
 * Aggregated protocol versions: 5.0, 4.2.2018
 * Version selection: automatic by send time, or forced by preference
 *
 * Generated from the Omi binary model library
 *
 * Models:
 *   Nasdaq.NsmEquities.Orders.Ouch.v5.0
 *   Nasdaq.NsmEquities.Orders.Ouch.v4.2.2018
 *
 * Authors: Omi Developers
 *
 * The Open Markets Initiative
 *   https://openmarketsinitiative.com
 *
 * Copyright (c) 2026 Scaled Sources LLC.
 *   https://www.scaledsources.com
 *
 * This dissector code is contributed by The Open Markets Initiative under
 * the license noted below.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/proto_data.h>
#include <wsutil/array.h>

void proto_register_nsmequities_orders(void);
void proto_reg_handoff_nsmequities_orders(void);

static dissector_handle_t nsmequities_orders_handle;

static int proto_nsmequities_orders;

/*
 * NsmEquities Orders Protocol
 */

#define NSMEQUITIES_ORDERS_PROTOCOL_NAME "Nasdaq Ouch Orders"
#define NSMEQUITIES_ORDERS_PROTOCOL_SHORT "NSMEQUITIES.ORDERS"
#define NSMEQUITIES_ORDERS_PROTOCOL_FILTER "nsmequities.orders"

/*
 * NsmEquities Orders Header
 */

#define NSMEQUITIES_ORDERS_CLIENT_PACKET_HEADER_SIZE 3 /* Client Soup Bin Tcp Packet */
#define NSMEQUITIES_ORDERS_SERVER_PACKET_HEADER_SIZE 3 /* Server Soup Bin Tcp Packet */

/*
 * NsmEquities Orders Field Handles
 */

static int hf_nsmequities_orders_accepted_sequence_number;
static int hf_nsmequities_orders_accepted_session;
static int hf_nsmequities_orders_account_query_optional_field;
static int hf_nsmequities_orders_account_query_response_optional_field;
static int hf_nsmequities_orders_aiq_canceled_optional_field;
static int hf_nsmequities_orders_aiq_group_id;
static int hf_nsmequities_orders_aiq_strategy;
static int hf_nsmequities_orders_appendage_length;
static int hf_nsmequities_orders_appendage_length_v50;
static int hf_nsmequities_orders_bbo_weight_indicator;
static int hf_nsmequities_orders_broken_trade_optional_field;
static int hf_nsmequities_orders_broken_trade_reason;
static int hf_nsmequities_orders_buy_sell_indicator;
static int hf_nsmequities_orders_cancel_order_optional_field;
static int hf_nsmequities_orders_cancel_order_reason;
static int hf_nsmequities_orders_cancel_pending_optional_field;
static int hf_nsmequities_orders_cancel_reject_optional_field;
static int hf_nsmequities_orders_canceled_message_optional_field;
static int hf_nsmequities_orders_capacity;
static int hf_nsmequities_orders_clordid;
static int hf_nsmequities_orders_client_packet_type;
static int hf_nsmequities_orders_cross_type;
static int hf_nsmequities_orders_customer_type;
static int hf_nsmequities_orders_customer_type_v422018;
static int hf_nsmequities_orders_debug_text;
static int hf_nsmequities_orders_decrement_shares;
static int hf_nsmequities_orders_disable_order_entry_request_optional_field;
static int hf_nsmequities_orders_disable_order_entry_response_optional_field;
static int hf_nsmequities_orders_discretion_peg_offset;
static int hf_nsmequities_orders_discretion_price;
static int hf_nsmequities_orders_discretion_price_type;
static int hf_nsmequities_orders_display;
static int hf_nsmequities_orders_display_price;
static int hf_nsmequities_orders_display_quantity;
static int hf_nsmequities_orders_enable_order_entry_request_optional_field;
static int hf_nsmequities_orders_enable_order_entry_response_optional_field;
static int hf_nsmequities_orders_enter_order_optional_field;
static int hf_nsmequities_orders_event_code;
static int hf_nsmequities_orders_executed_shares;
static int hf_nsmequities_orders_execution_price;
static int hf_nsmequities_orders_execution_price_v422018;
static int hf_nsmequities_orders_existing_order_token;
static int hf_nsmequities_orders_expire_time;
static int hf_nsmequities_orders_firm;
static int hf_nsmequities_orders_group_id;
static int hf_nsmequities_orders_handle_inst;
static int hf_nsmequities_orders_inter_market_sweep_eligibility;
static int hf_nsmequities_orders_intermarket_sweep_eligibility;
static int hf_nsmequities_orders_liquidity_flag;
static int hf_nsmequities_orders_locate_broker;
static int hf_nsmequities_orders_mass_cancel_request_optional_field;
static int hf_nsmequities_orders_mass_cancel_response_optional_field;
static int hf_nsmequities_orders_match_number;
static int hf_nsmequities_orders_max_floor;
static int hf_nsmequities_orders_min_qty;
static int hf_nsmequities_orders_minimum_quantity;
static int hf_nsmequities_orders_modify_order_optional_field;
static int hf_nsmequities_orders_next_user_ref_num;
static int hf_nsmequities_orders_optional_field_length;
static int hf_nsmequities_orders_order_accepted_optional_field;
static int hf_nsmequities_orders_order_cancel_reason;
static int hf_nsmequities_orders_order_executed_optional_field;
static int hf_nsmequities_orders_order_modified_optional_field;
static int hf_nsmequities_orders_order_priority_update_optional_field;
static int hf_nsmequities_orders_order_reference_number;
static int hf_nsmequities_orders_order_restated_optional_field;
static int hf_nsmequities_orders_order_restated_reason;
static int hf_nsmequities_orders_order_state;
static int hf_nsmequities_orders_order_token;
static int hf_nsmequities_orders_orig_user_ref_num;
static int hf_nsmequities_orders_packet_length;
static int hf_nsmequities_orders_password;
static int hf_nsmequities_orders_peg_offset;
static int hf_nsmequities_orders_post_only;
static int hf_nsmequities_orders_previous_order_token;
static int hf_nsmequities_orders_price;
static int hf_nsmequities_orders_price_v422018;
static int hf_nsmequities_orders_price_type;
static int hf_nsmequities_orders_quantity;
static int hf_nsmequities_orders_quantity_prevented_from_trading;
static int hf_nsmequities_orders_random_reserves;
static int hf_nsmequities_orders_reason;
static int hf_nsmequities_orders_reference_price;
static int hf_nsmequities_orders_reference_price_type;
static int hf_nsmequities_orders_reject_reason_code;
static int hf_nsmequities_orders_rejected_order_optional_field;
static int hf_nsmequities_orders_rejected_order_reason;
static int hf_nsmequities_orders_rejected_order_reason_v422018;
static int hf_nsmequities_orders_replace_order_optional_field;
static int hf_nsmequities_orders_replaced_message_optional_field;
static int hf_nsmequities_orders_replacement_order_token;
static int hf_nsmequities_orders_requested_sequence_number;
static int hf_nsmequities_orders_requested_session;
static int hf_nsmequities_orders_route;
static int hf_nsmequities_orders_secondary_ord_ref_num;
static int hf_nsmequities_orders_sequenced_message_type;
static int hf_nsmequities_orders_server_packet_type;
static int hf_nsmequities_orders_shares;
static int hf_nsmequities_orders_shares_located;
static int hf_nsmequities_orders_side;
static int hf_nsmequities_orders_stock;
static int hf_nsmequities_orders_symbol;
static int hf_nsmequities_orders_time_in_force;
static int hf_nsmequities_orders_time_in_force_v422018;
static int hf_nsmequities_orders_timestamp;
static int hf_nsmequities_orders_timestamp_v422018;
static int hf_nsmequities_orders_trade_now;
static int hf_nsmequities_orders_unsequenced_message_type;
static int hf_nsmequities_orders_user_ref_idx;
static int hf_nsmequities_orders_user_ref_num;
static int hf_nsmequities_orders_username;
static int hf_nsmequities_orders_time_of_day;
static int hf_nsmequities_orders_utc;
static int hf_nsmequities_orders_local;
static int hf_nsmequities_orders_elapsed_nanoseconds;

/* The time of day a timestamp reads as, beneath the instant it names */
#define NSMEQUITIES_ORDERS_TIME_OF_DAY_NAME "Time Of Day"
#define NSMEQUITIES_ORDERS_TIME_OF_DAY_FILTER "nsmequities.orders.timeofday"
#define NSMEQUITIES_ORDERS_TIME_OF_DAY_DESCRIPTION "Time of day composed from the second the feed established and the count within it"

/* The instant a time of day names, dated by the frame that carried it */
#define NSMEQUITIES_ORDERS_UTC_NAME "Utc"
#define NSMEQUITIES_ORDERS_UTC_FILTER "nsmequities.orders.utc"
#define NSMEQUITIES_ORDERS_UTC_DESCRIPTION "The instant the time of day names, dated by the frame that carried the message"

/* The same instant as the reader's own clock reads it */
#define NSMEQUITIES_ORDERS_LOCAL_NAME "Local"
#define NSMEQUITIES_ORDERS_LOCAL_FILTER "nsmequities.orders.local"
#define NSMEQUITIES_ORDERS_LOCAL_DESCRIPTION "The instant the time of day names, in the reader's own timezone"

/* The count the wire carries, under the reading of it */
#define NSMEQUITIES_ORDERS_ELAPSED_NANOSECONDS_NAME "Nanoseconds"
#define NSMEQUITIES_ORDERS_ELAPSED_NANOSECONDS_FILTER "nsmequities.orders.elapsed.nanoseconds"
#define NSMEQUITIES_ORDERS_ELAPSED_NANOSECONDS_DESCRIPTION "The count since midnight the message states, as the wire carries it"

/*
 * NsmEquities Orders Subtrees
 */

static int ett_nsmequities_orders;
static int ett_nsmequities_orders_header;
static int ett_nsmequities_orders_message;
static int ett_nsmequities_orders_timestamp;
static int ett_nsmequities_orders_client_packet_header;
static int ett_nsmequities_orders_enter_order_appendage;
static int ett_nsmequities_orders_replace_order_appendage;
static int ett_nsmequities_orders_cancel_order_appendage;
static int ett_nsmequities_orders_modify_order_appendage;
static int ett_nsmequities_orders_account_query_appendage;
static int ett_nsmequities_orders_mass_cancel_request_appendage;
static int ett_nsmequities_orders_disable_order_entry_request_appendage;
static int ett_nsmequities_orders_enable_order_entry_request_appendage;
static int ett_nsmequities_orders_server_packet_header;
static int ett_nsmequities_orders_order_accepted_appendage;
static int ett_nsmequities_orders_replaced_message_appendage;
static int ett_nsmequities_orders_canceled_message_appendage;
static int ett_nsmequities_orders_aiq_canceled_appendage;
static int ett_nsmequities_orders_order_executed_appendage;
static int ett_nsmequities_orders_broken_trade_appendage;
static int ett_nsmequities_orders_rejected_order_appendage;
static int ett_nsmequities_orders_cancel_pending_appendage;
static int ett_nsmequities_orders_cancel_reject_appendage;
static int ett_nsmequities_orders_order_priority_update_appendage;
static int ett_nsmequities_orders_order_modified_appendage;
static int ett_nsmequities_orders_order_restated_appendage;
static int ett_nsmequities_orders_account_query_response_appendage;
static int ett_nsmequities_orders_mass_cancel_response_appendage;
static int ett_nsmequities_orders_disable_order_entry_response_appendage;
static int ett_nsmequities_orders_enable_order_entry_response_appendage;

/*
 * NsmEquities Orders Expert Information
 */

/* Message length does not account for the parsed fields */
#define NSMEQUITIES_ORDERS_LENGTH_EXPERT_FILTER "nsmequities.orders.length.invalid"
#define NSMEQUITIES_ORDERS_LENGTH_EXPERT_GROUP PI_MALFORMED
#define NSMEQUITIES_ORDERS_LENGTH_EXPERT_SEVERITY PI_ERROR
#define NSMEQUITIES_ORDERS_LENGTH_EXPERT_SUMMARY "Message length does not account for the parsed fields"

static expert_field ei_nsmequities_orders_length;

/*
 * NsmEquities Orders Preferences
 */

#define NSMEQUITIES_ORDERS_VERSION_PREFERENCE_NAME "version"
#define NSMEQUITIES_ORDERS_VERSION_PREFERENCE_TITLE "Protocol version"
#define NSMEQUITIES_ORDERS_VERSION_PREFERENCE_DESCRIPTION "Version used when dissecting, Automatic selects by the packet send time"

#define NSMEQUITIES_ORDERS_VERSION_AUTOMATIC 0
#define NSMEQUITIES_ORDERS_VERSION_5_0     1
#define NSMEQUITIES_ORDERS_VERSION_4_2_2018     2

static const enum_val_t nsmequities_orders_version_vals[] = {
    { "automatic", "Automatic (by send time)", NSMEQUITIES_ORDERS_VERSION_AUTOMATIC },
    { "v5.0", "5.0", NSMEQUITIES_ORDERS_VERSION_5_0 },
    { "v4.2.2018", "4.2.2018", NSMEQUITIES_ORDERS_VERSION_4_2_2018 },
    { NULL, NULL, 0 }
};

/* The version a frame was read with, for the protocol line */
static const char *
nsmequities_orders_version_name(int version)
{
    switch (version) {
    case NSMEQUITIES_ORDERS_VERSION_5_0:
        return "5.0";
    case NSMEQUITIES_ORDERS_VERSION_4_2_2018:
        return "4.2.2018";
    }

    return "";
}

static int nsmequities_orders_pref_version = NSMEQUITIES_ORDERS_VERSION_AUTOMATIC;

/* Version effective times, seconds since the unix epoch */
#define NSMEQUITIES_ORDERS_EFFECTIVE_5_0 UINT64_C(1668384000) /* 2022-11-14 */

/* Show preferences, one per message and struct */
#define NSMEQUITIES_ORDERS_SHOW_HEADERS_PREFERENCE_NAME "show.headers"
#define NSMEQUITIES_ORDERS_SHOW_HEADERS_PREFERENCE_TITLE "Show Headers"
#define NSMEQUITIES_ORDERS_SHOW_HEADERS_PREFERENCE_DESCRIPTION "Show Headers in the protocol tree"

#define NSMEQUITIES_ORDERS_SHOW_SESSION_MESSAGES_PREFERENCE_NAME "show.sessionmessages"
#define NSMEQUITIES_ORDERS_SHOW_SESSION_MESSAGES_PREFERENCE_TITLE "Show Session Messages"
#define NSMEQUITIES_ORDERS_SHOW_SESSION_MESSAGES_PREFERENCE_DESCRIPTION "Show Session Messages in the protocol tree"

#define NSMEQUITIES_ORDERS_SHOW_APPLICATION_MESSAGES_PREFERENCE_NAME "show.applicationmessages"
#define NSMEQUITIES_ORDERS_SHOW_APPLICATION_MESSAGES_PREFERENCE_TITLE "Show Application Messages"
#define NSMEQUITIES_ORDERS_SHOW_APPLICATION_MESSAGES_PREFERENCE_DESCRIPTION "Show Application Messages in the protocol tree"

#define NSMEQUITIES_ORDERS_SHOW_STRUCTS_PREFERENCE_NAME "show.structs"
#define NSMEQUITIES_ORDERS_SHOW_STRUCTS_PREFERENCE_TITLE "Show Structs"
#define NSMEQUITIES_ORDERS_SHOW_STRUCTS_PREFERENCE_DESCRIPTION "Show Structs in the protocol tree"

static bool nsmequities_orders_show_headers = true;
static bool nsmequities_orders_show_session_messages = true;
static bool nsmequities_orders_show_application_messages = true;
static bool nsmequities_orders_show_structs = true;

/* Decimal places shown, the wire precision by default */
#define NSMEQUITIES_ORDERS_DECIMAL_PREFERENCE_NAME "decimal.places"
#define NSMEQUITIES_ORDERS_DECIMAL_PREFERENCE_TITLE "Decimal places"
#define NSMEQUITIES_ORDERS_DECIMAL_PREFERENCE_DESCRIPTION "Decimal places shown for scaled fields, the default is the full wire precision"

static unsigned nsmequities_orders_pref_decimal_places = 4;

/* Timestamp read as a time of day, which is the default */
#define NSMEQUITIES_ORDERS_READ_TIMESTAMP_PREFERENCE_NAME "read.timestamp"
#define NSMEQUITIES_ORDERS_READ_TIMESTAMP_PREFERENCE_TITLE "Read Timestamp as a time"
#define NSMEQUITIES_ORDERS_READ_TIMESTAMP_PREFERENCE_DESCRIPTION "Read Timestamp as a time of day, with the instant it names beneath it. Off states the nanoseconds since midnight the wire carries and nothing else"

static bool nsmequities_orders_pref_read_timestamp = true;

/* Connection roles, Client is the initiator, Server is the acceptor */
#define NSMEQUITIES_ORDERS_ROLE_RESOLVE 0
#define NSMEQUITIES_ORDERS_ROLE_INITIATOR 1
#define NSMEQUITIES_ORDERS_ROLE_ACCEPTOR 2

#define NSMEQUITIES_ORDERS_ASSUME_ROLE_PREFERENCE_NAME "role.assume"
#define NSMEQUITIES_ORDERS_ASSUME_ROLE_PREFERENCE_TITLE "Assume role"
#define NSMEQUITIES_ORDERS_ASSUME_ROLE_PREFERENCE_DESCRIPTION "Connection role assumed for every frame, for captures that start mid conversation"
#define NSMEQUITIES_ORDERS_ACCEPTOR_PORT_PREFERENCE_NAME "role.acceptorport"
#define NSMEQUITIES_ORDERS_ACCEPTOR_PORT_PREFERENCE_TITLE "Acceptor port"
#define NSMEQUITIES_ORDERS_ACCEPTOR_PORT_PREFERENCE_DESCRIPTION "Port the acceptor listens on, 0 resolves each frame's role from its conversation"
#define NSMEQUITIES_ORDERS_SWAP_SIDES_PREFERENCE_NAME "role.swapsides"
#define NSMEQUITIES_ORDERS_SWAP_SIDES_PREFERENCE_TITLE "Swap sides"
#define NSMEQUITIES_ORDERS_SWAP_SIDES_PREFERENCE_DESCRIPTION "The first frame seen of each conversation was the acceptor's, not the initiator's, for captures that start mid conversation"

static int nsmequities_orders_pref_assume_role = NSMEQUITIES_ORDERS_ROLE_RESOLVE;
static unsigned nsmequities_orders_pref_acceptor_port = 0;
static bool nsmequities_orders_pref_swap_sides = false;

static const enum_val_t nsmequities_orders_assume_role_vals[] = {
    { "resolve", "Resolve from the conversation", NSMEQUITIES_ORDERS_ROLE_RESOLVE },
    { "initiator", "Initiator (Client)", NSMEQUITIES_ORDERS_ROLE_INITIATOR },
    { "acceptor", "Acceptor (Server)", NSMEQUITIES_ORDERS_ROLE_ACCEPTOR },
    { NULL, NULL, 0 }
};

/* Ports the feed arrives on, assigned per deployment */
#define NSMEQUITIES_ORDERS_PORTS_PREFERENCE_NAME "ports"
#define NSMEQUITIES_ORDERS_PORTS_PREFERENCE_TITLE "Ports"
#define NSMEQUITIES_ORDERS_PORTS_PREFERENCE_DESCRIPTION "Ports this feed arrives on, set to the ports the exchange assigned this deployment"
#define NSMEQUITIES_ORDERS_PORTS_PREFERENCE_DEFAULT "8001,8003"
#define NSMEQUITIES_ORDERS_PORTS_PREFERENCE_MAXIMUM 65535

static range_t *nsmequities_orders_pref_ports;

/*
 * NsmEquities Orders Methods
 */

/* Select the protocol version, from the preference, the
   schema the frame declares, or the capture clock in seconds
   since the unix epoch */
static int
nsmequities_orders_version(uint64_t seconds)
{
    if (nsmequities_orders_pref_version != NSMEQUITIES_ORDERS_VERSION_AUTOMATIC) {
        return nsmequities_orders_pref_version;
    }

    if (seconds >= NSMEQUITIES_ORDERS_EFFECTIVE_5_0) {
        return NSMEQUITIES_ORDERS_VERSION_5_0;
    }

    return NSMEQUITIES_ORDERS_VERSION_4_2_2018;
}

/* Label an offset from midnight as the clock reads it */
static void
nsmequities_orders_time_of_day_label(char *buf, size_t size, const nstime_t *time)
{
    uint32_t seconds = (uint32_t)time->secs;

    snprintf(buf, size, "%02u:%02u:%02u.%09u",
        seconds / 3600, (seconds / 60) % 60, seconds % 60, (uint32_t)time->nsecs);
}

/* What this protocol remembers across the frames of a conversation */
typedef struct nsmequities_orders_conversation {
    address initiator;
    uint32_t port;
    bool swapped;
} nsmequities_orders_conversation;

/* Record of the frame's conversation, created on its first frame */
static nsmequities_orders_conversation *
nsmequities_orders_conversation_of(packet_info *pinfo)
{
    conversation_t *conversation = find_or_create_conversation(pinfo);
    nsmequities_orders_conversation *state = (nsmequities_orders_conversation *)conversation_get_proto_data(conversation, proto_nsmequities_orders);

    if (state == NULL) {
        state = wmem_new0(wmem_file_scope(), nsmequities_orders_conversation);
        copy_address_wmem(wmem_file_scope(), &state->initiator, &pinfo->src);
        state->port = pinfo->srcport;
        conversation_add_proto_data(conversation, proto_nsmequities_orders, state);
    }

    return state;
}

/* Date a count from midnight by the frame that carried it. The day is
   settled once per frame, from the first time of day read out of it: the
   messages a frame carries share the day it arrived, and a later pass over
   the frame must read what the first one settled on */
static void
nsmequities_orders_utc(packet_info *pinfo, uint64_t seconds, uint32_t nanoseconds, nstime_t *instant)
{
    int64_t *midnight = (int64_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_nsmequities_orders, 1);

    if (midnight == NULL) {
        int64_t settled = (int64_t)pinfo->abs_ts.secs - (int64_t)seconds;

        midnight = wmem_new0(wmem_file_scope(), int64_t);
        *midnight = (settled + (settled < 0 ? -450 : 450)) / 900 * 900;
        p_add_proto_data(wmem_file_scope(), pinfo, proto_nsmequities_orders, 1, midnight);
    }

    instant->secs = (time_t)(*midnight + (int64_t)seconds);
    instant->nsecs = (int)nanoseconds;
}

/* Cap the fraction at the preferred decimal places */
static void
nsmequities_orders_decimal_places(char *buf)
{
    char *point = strchr(buf, '.');

    if (point == NULL) {
        return;
    }

    unsigned places = nsmequities_orders_pref_decimal_places;

    if (places >= strlen(point + 1)) {
        return;
    }

    if (places == 0) {
        *point = '\0';
        return;
    }

    point[1 + places] = '\0';
}

/* Format an implied 4 decimal place value */
static void
nsmequities_orders_format_decimal_4_32(char *buf, uint32_t raw)
{
    int64_t value = (int32_t)raw;
    int64_t units = value / 10000;
    int64_t fraction = value % 10000;

    if (fraction < 0) {
        fraction = -fraction;
    }

    if (value < 0 && units == 0) {
        snprintf(buf, ITEM_LABEL_LENGTH, "-0.%04" PRId64, fraction);
    }
    else {
        snprintf(buf, ITEM_LABEL_LENGTH, "%" PRId64 ".%04" PRId64, units, fraction);
    }

    nsmequities_orders_decimal_places(buf);
}

/* Format an implied 4 decimal place value */
static void
nsmequities_orders_format_decimal_4_32_unsigned(char *buf, uint32_t raw)
{
    uint64_t value = (uint32_t)raw;
    uint64_t units = value / 10000;
    uint64_t fraction = value % 10000;

    snprintf(buf, ITEM_LABEL_LENGTH, "%" PRIu64 ".%04" PRIu64, units, fraction);

    nsmequities_orders_decimal_places(buf);
}

/* Format an implied 4 decimal place value */
static void
nsmequities_orders_format_decimal_4_64_unsigned(char *buf, uint64_t raw)
{
    uint64_t value = (uint64_t)raw;
    uint64_t units = value / 10000;
    uint64_t fraction = value % 10000;

    snprintf(buf, ITEM_LABEL_LENGTH, "%" PRIu64 ".%04" PRIu64, units, fraction);

    nsmequities_orders_decimal_places(buf);
}

/*
 * NsmEquities Orders Fields
 */

/* Accepted Sequence Number */
#define NSMEQUITIES_ORDERS_ACCEPTED_SEQUENCE_NUMBER_NAME        "Accepted Sequence Number"
#define NSMEQUITIES_ORDERS_ACCEPTED_SEQUENCE_NUMBER_DESCRIPTION "The sequence number in ASCII of the next Sequenced Message to be sent. Left padded with spaces."
#define NSMEQUITIES_ORDERS_ACCEPTED_SEQUENCE_NUMBER_FILTER      "nsmequities.orders.acceptedsequencenumber"
#define NSMEQUITIES_ORDERS_ACCEPTED_SEQUENCE_NUMBER_TYPE        FT_UINT64
#define NSMEQUITIES_ORDERS_ACCEPTED_SEQUENCE_NUMBER_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_ACCEPTED_SEQUENCE_NUMBER_MASK        0x0
#define NSMEQUITIES_ORDERS_ACCEPTED_SEQUENCE_NUMBER_ENCODING    ENC_ASCII
#define NSMEQUITIES_ORDERS_ACCEPTED_SEQUENCE_NUMBER_SIZE        20

static unsigned
parse_nsmequities_orders_accepted_sequence_number(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    const char *text = (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset, NSMEQUITIES_ORDERS_ACCEPTED_SEQUENCE_NUMBER_SIZE, ENC_ASCII);

    uint64_t value = (uint64_t)strtoull(text, NULL, 10);

    proto_tree_add_uint64(tree, hf_nsmequities_orders_accepted_sequence_number, tvb, offset, NSMEQUITIES_ORDERS_ACCEPTED_SEQUENCE_NUMBER_SIZE, value);

    return offset + NSMEQUITIES_ORDERS_ACCEPTED_SEQUENCE_NUMBER_SIZE;
}

/* Accepted Session */
#define NSMEQUITIES_ORDERS_ACCEPTED_SESSION_NAME        "Accepted Session"
#define NSMEQUITIES_ORDERS_ACCEPTED_SESSION_DESCRIPTION "The session ID of the session that is now logged into. Left padded with spaces."
#define NSMEQUITIES_ORDERS_ACCEPTED_SESSION_FILTER      "nsmequities.orders.acceptedsession"
#define NSMEQUITIES_ORDERS_ACCEPTED_SESSION_TYPE        FT_STRING
#define NSMEQUITIES_ORDERS_ACCEPTED_SESSION_DISPLAY     BASE_NONE
#define NSMEQUITIES_ORDERS_ACCEPTED_SESSION_MASK        0x0
#define NSMEQUITIES_ORDERS_ACCEPTED_SESSION_ENCODING    ENC_ASCII
#define NSMEQUITIES_ORDERS_ACCEPTED_SESSION_SIZE        10

static unsigned
parse_nsmequities_orders_accepted_session(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_accepted_session, tvb, offset, NSMEQUITIES_ORDERS_ACCEPTED_SESSION_SIZE, NSMEQUITIES_ORDERS_ACCEPTED_SESSION_ENCODING);

    return offset + NSMEQUITIES_ORDERS_ACCEPTED_SESSION_SIZE;
}

/* Account Query Optional Field values the dispatch switches on */
#define NSMEQUITIES_ORDERS_ACCOUNT_QUERY_OPTIONAL_FIELD_USERREFIDX 28

/* Account Query Optional Field */
#define NSMEQUITIES_ORDERS_ACCOUNT_QUERY_OPTIONAL_FIELD_NAME        "Account Query Optional Field"
#define NSMEQUITIES_ORDERS_ACCOUNT_QUERY_OPTIONAL_FIELD_DESCRIPTION "Appendage Id"
#define NSMEQUITIES_ORDERS_ACCOUNT_QUERY_OPTIONAL_FIELD_FILTER      "nsmequities.orders.accountqueryoptionalfield"
#define NSMEQUITIES_ORDERS_ACCOUNT_QUERY_OPTIONAL_FIELD_TYPE        FT_UINT8
#define NSMEQUITIES_ORDERS_ACCOUNT_QUERY_OPTIONAL_FIELD_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_ACCOUNT_QUERY_OPTIONAL_FIELD_MASK        0x0
#define NSMEQUITIES_ORDERS_ACCOUNT_QUERY_OPTIONAL_FIELD_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_ACCOUNT_QUERY_OPTIONAL_FIELD_SIZE        1

static const value_string nsmequities_orders_account_query_optional_field_vals[] = {
    { NSMEQUITIES_ORDERS_ACCOUNT_QUERY_OPTIONAL_FIELD_USERREFIDX, "UserRefIdx" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_account_query_optional_field(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_account_query_optional_field, tvb, offset, NSMEQUITIES_ORDERS_ACCOUNT_QUERY_OPTIONAL_FIELD_SIZE, NSMEQUITIES_ORDERS_ACCOUNT_QUERY_OPTIONAL_FIELD_ENCODING);

    return offset + NSMEQUITIES_ORDERS_ACCOUNT_QUERY_OPTIONAL_FIELD_SIZE;
}

/* Account Query Response Optional Field values the dispatch switches on */
#define NSMEQUITIES_ORDERS_ACCOUNT_QUERY_RESPONSE_OPTIONAL_FIELD_USERREFIDX 28

/* Account Query Response Optional Field */
#define NSMEQUITIES_ORDERS_ACCOUNT_QUERY_RESPONSE_OPTIONAL_FIELD_NAME        "Account Query Response Optional Field"
#define NSMEQUITIES_ORDERS_ACCOUNT_QUERY_RESPONSE_OPTIONAL_FIELD_DESCRIPTION "Appendage Id"
#define NSMEQUITIES_ORDERS_ACCOUNT_QUERY_RESPONSE_OPTIONAL_FIELD_FILTER      "nsmequities.orders.accountqueryresponseoptionalfield"
#define NSMEQUITIES_ORDERS_ACCOUNT_QUERY_RESPONSE_OPTIONAL_FIELD_TYPE        FT_UINT8
#define NSMEQUITIES_ORDERS_ACCOUNT_QUERY_RESPONSE_OPTIONAL_FIELD_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_ACCOUNT_QUERY_RESPONSE_OPTIONAL_FIELD_MASK        0x0
#define NSMEQUITIES_ORDERS_ACCOUNT_QUERY_RESPONSE_OPTIONAL_FIELD_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_ACCOUNT_QUERY_RESPONSE_OPTIONAL_FIELD_SIZE        1

static const value_string nsmequities_orders_account_query_response_optional_field_vals[] = {
    { NSMEQUITIES_ORDERS_ACCOUNT_QUERY_RESPONSE_OPTIONAL_FIELD_USERREFIDX, "UserRefIdx" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_account_query_response_optional_field(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_account_query_response_optional_field, tvb, offset, NSMEQUITIES_ORDERS_ACCOUNT_QUERY_RESPONSE_OPTIONAL_FIELD_SIZE, NSMEQUITIES_ORDERS_ACCOUNT_QUERY_RESPONSE_OPTIONAL_FIELD_ENCODING);

    return offset + NSMEQUITIES_ORDERS_ACCOUNT_QUERY_RESPONSE_OPTIONAL_FIELD_SIZE;
}

/* Aiq Canceled Optional Field values the dispatch switches on */
#define NSMEQUITIES_ORDERS_AIQ_CANCELED_OPTIONAL_FIELD_USERREFIDX 28

/* Aiq Canceled Optional Field */
#define NSMEQUITIES_ORDERS_AIQ_CANCELED_OPTIONAL_FIELD_NAME        "Aiq Canceled Optional Field"
#define NSMEQUITIES_ORDERS_AIQ_CANCELED_OPTIONAL_FIELD_DESCRIPTION "Appendage Id"
#define NSMEQUITIES_ORDERS_AIQ_CANCELED_OPTIONAL_FIELD_FILTER      "nsmequities.orders.aiqcanceledoptionalfield"
#define NSMEQUITIES_ORDERS_AIQ_CANCELED_OPTIONAL_FIELD_TYPE        FT_UINT8
#define NSMEQUITIES_ORDERS_AIQ_CANCELED_OPTIONAL_FIELD_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_AIQ_CANCELED_OPTIONAL_FIELD_MASK        0x0
#define NSMEQUITIES_ORDERS_AIQ_CANCELED_OPTIONAL_FIELD_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_AIQ_CANCELED_OPTIONAL_FIELD_SIZE        1

static const value_string nsmequities_orders_aiq_canceled_optional_field_vals[] = {
    { NSMEQUITIES_ORDERS_AIQ_CANCELED_OPTIONAL_FIELD_USERREFIDX, "UserRefIdx" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_aiq_canceled_optional_field(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_aiq_canceled_optional_field, tvb, offset, NSMEQUITIES_ORDERS_AIQ_CANCELED_OPTIONAL_FIELD_SIZE, NSMEQUITIES_ORDERS_AIQ_CANCELED_OPTIONAL_FIELD_ENCODING);

    return offset + NSMEQUITIES_ORDERS_AIQ_CANCELED_OPTIONAL_FIELD_SIZE;
}

/* Aiq Group Id */
#define NSMEQUITIES_ORDERS_AIQ_GROUP_ID_NAME        "Aiq Group Id"
#define NSMEQUITIES_ORDERS_AIQ_GROUP_ID_DESCRIPTION "Specified to enable self match prevention at a more granular level within a given matching level"
#define NSMEQUITIES_ORDERS_AIQ_GROUP_ID_FILTER      "nsmequities.orders.aiqgroupid"
#define NSMEQUITIES_ORDERS_AIQ_GROUP_ID_TYPE        FT_STRING
#define NSMEQUITIES_ORDERS_AIQ_GROUP_ID_DISPLAY     BASE_NONE
#define NSMEQUITIES_ORDERS_AIQ_GROUP_ID_MASK        0x0
#define NSMEQUITIES_ORDERS_AIQ_GROUP_ID_ENCODING    ENC_ASCII
#define NSMEQUITIES_ORDERS_AIQ_GROUP_ID_SIZE        2

static unsigned
parse_nsmequities_orders_aiq_group_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_aiq_group_id, tvb, offset, NSMEQUITIES_ORDERS_AIQ_GROUP_ID_SIZE, NSMEQUITIES_ORDERS_AIQ_GROUP_ID_ENCODING);

    return offset + NSMEQUITIES_ORDERS_AIQ_GROUP_ID_SIZE;
}

/* Aiq Strategy */
#define NSMEQUITIES_ORDERS_AIQ_STRATEGY_NAME        "Aiq Strategy"
#define NSMEQUITIES_ORDERS_AIQ_STRATEGY_DESCRIPTION "AIQ strategy used on the cancelled order."
#define NSMEQUITIES_ORDERS_AIQ_STRATEGY_FILTER      "nsmequities.orders.aiqstrategy"
#define NSMEQUITIES_ORDERS_AIQ_STRATEGY_TYPE        FT_CHAR
#define NSMEQUITIES_ORDERS_AIQ_STRATEGY_DISPLAY     BASE_HEX
#define NSMEQUITIES_ORDERS_AIQ_STRATEGY_MASK        0x0
#define NSMEQUITIES_ORDERS_AIQ_STRATEGY_ENCODING    ENC_ASCII
#define NSMEQUITIES_ORDERS_AIQ_STRATEGY_SIZE        1

static const value_string nsmequities_orders_aiq_strategy_vals[] = {
    { '*', "Use Port Default" },
    { 'N', "Disabled" },
    { 'Y', "Firm Level Decrement Both No Details" },
    { 'D', "Firm Level Decrement Both" },
    { 'O', "Firm Level Cancel Oldest" },
    { 'W', "Firm Level Cancel Newest" },
    { 'R', "Firm Level Use Remover" },
    { 'y', "Organization Level Decrement Both No Details" },
    { 'd', "Organization Level Decrement Both" },
    { 'o', "Organization Level Cancel Oldest" },
    { 'w', "Organization Level Cancel Newest" },
    { 'r', "Organization Level Use Remover" },
    { 'Z', "Affiliate Level Decrement Both No Details" },
    { 'E', "Affiliate Level Decrement Both" },
    { 'P', "Affiliate Level Cancel Oldest" },
    { 'X', "Affiliate Level Cancel Newest" },
    { 'S', "Affiliate Level Use Remover" },
    { '0', "Match Any Level Decrement Both No Details" },
    { '1', "Match Any Level Decrement Both" },
    { '2', "Match Any Level Cancel Oldest" },
    { '4', "Match Any Level Cancel Newest" },
    { '5', "Match Any Level Use Remover" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_aiq_strategy(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_aiq_strategy, tvb, offset, NSMEQUITIES_ORDERS_AIQ_STRATEGY_SIZE, NSMEQUITIES_ORDERS_AIQ_STRATEGY_ENCODING);

    return offset + NSMEQUITIES_ORDERS_AIQ_STRATEGY_SIZE;
}

/* Appendage Length */
#define NSMEQUITIES_ORDERS_APPENDAGE_LENGTH_NAME        "Appendage Length"
#define NSMEQUITIES_ORDERS_APPENDAGE_LENGTH_DESCRIPTION "The length of the remaining Optional Appendage field."
#define NSMEQUITIES_ORDERS_APPENDAGE_LENGTH_FILTER      "nsmequities.orders.appendagelength"
#define NSMEQUITIES_ORDERS_APPENDAGE_LENGTH_TYPE        FT_UINT16
#define NSMEQUITIES_ORDERS_APPENDAGE_LENGTH_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_APPENDAGE_LENGTH_MASK        0x0
#define NSMEQUITIES_ORDERS_APPENDAGE_LENGTH_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_APPENDAGE_LENGTH_SIZE        2

static unsigned
parse_nsmequities_orders_appendage_length(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_appendage_length, tvb, offset, NSMEQUITIES_ORDERS_APPENDAGE_LENGTH_SIZE, NSMEQUITIES_ORDERS_APPENDAGE_LENGTH_ENCODING);

    return offset + NSMEQUITIES_ORDERS_APPENDAGE_LENGTH_SIZE;
}

/* Appendage Length V50 */
#define NSMEQUITIES_ORDERS_APPENDAGE_LENGTH_V50_NAME        "Appendage Length"
#define NSMEQUITIES_ORDERS_APPENDAGE_LENGTH_V50_DESCRIPTION "The length of the remaining Optional Appendage field."
#define NSMEQUITIES_ORDERS_APPENDAGE_LENGTH_V50_FILTER      "nsmequities.orders.appendagelength"
#define NSMEQUITIES_ORDERS_APPENDAGE_LENGTH_V50_TYPE        FT_UINT16
#define NSMEQUITIES_ORDERS_APPENDAGE_LENGTH_V50_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_APPENDAGE_LENGTH_V50_MASK        0x0
#define NSMEQUITIES_ORDERS_APPENDAGE_LENGTH_V50_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_APPENDAGE_LENGTH_V50_SIZE        2

static unsigned
parse_nsmequities_orders_appendage_length_v50(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_appendage_length_v50, tvb, offset, NSMEQUITIES_ORDERS_APPENDAGE_LENGTH_V50_SIZE, NSMEQUITIES_ORDERS_APPENDAGE_LENGTH_V50_ENCODING);

    return offset + NSMEQUITIES_ORDERS_APPENDAGE_LENGTH_V50_SIZE;
}

/* Bbo Weight Indicator */
#define NSMEQUITIES_ORDERS_BBO_WEIGHT_INDICATOR_NAME     "Bbo Weight Indicator"
#define NSMEQUITIES_ORDERS_BBO_WEIGHT_INDICATOR_FILTER   "nsmequities.orders.bboweightindicator"
#define NSMEQUITIES_ORDERS_BBO_WEIGHT_INDICATOR_TYPE     FT_CHAR
#define NSMEQUITIES_ORDERS_BBO_WEIGHT_INDICATOR_DISPLAY  BASE_HEX
#define NSMEQUITIES_ORDERS_BBO_WEIGHT_INDICATOR_MASK     0x0
#define NSMEQUITIES_ORDERS_BBO_WEIGHT_INDICATOR_ENCODING ENC_ASCII
#define NSMEQUITIES_ORDERS_BBO_WEIGHT_INDICATOR_SIZE     1

static const value_string nsmequities_orders_bbo_weight_indicator_vals[] = {
    { '0', "Weight 0 To 0.2 Percent" },
    { '1', "Weight 0.2 To 1 Percent" },
    { '2', "Weight 1 To 2 Percent" },
    { '3', "Greater Than 2%" },
    { ' ', "Unspecified" },
    { 'S', "Sets The Qbbo While Joining The Nbbo" },
    { 'N', "Improves The Nbbo Upon Entry" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_bbo_weight_indicator(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_bbo_weight_indicator, tvb, offset, NSMEQUITIES_ORDERS_BBO_WEIGHT_INDICATOR_SIZE, NSMEQUITIES_ORDERS_BBO_WEIGHT_INDICATOR_ENCODING);

    return offset + NSMEQUITIES_ORDERS_BBO_WEIGHT_INDICATOR_SIZE;
}

/* Broken Trade Optional Field values the dispatch switches on */
#define NSMEQUITIES_ORDERS_BROKEN_TRADE_OPTIONAL_FIELD_USERREFIDX 28

/* Broken Trade Optional Field */
#define NSMEQUITIES_ORDERS_BROKEN_TRADE_OPTIONAL_FIELD_NAME        "Broken Trade Optional Field"
#define NSMEQUITIES_ORDERS_BROKEN_TRADE_OPTIONAL_FIELD_DESCRIPTION "Appendage Id"
#define NSMEQUITIES_ORDERS_BROKEN_TRADE_OPTIONAL_FIELD_FILTER      "nsmequities.orders.brokentradeoptionalfield"
#define NSMEQUITIES_ORDERS_BROKEN_TRADE_OPTIONAL_FIELD_TYPE        FT_UINT8
#define NSMEQUITIES_ORDERS_BROKEN_TRADE_OPTIONAL_FIELD_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_BROKEN_TRADE_OPTIONAL_FIELD_MASK        0x0
#define NSMEQUITIES_ORDERS_BROKEN_TRADE_OPTIONAL_FIELD_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_BROKEN_TRADE_OPTIONAL_FIELD_SIZE        1

static const value_string nsmequities_orders_broken_trade_optional_field_vals[] = {
    { NSMEQUITIES_ORDERS_BROKEN_TRADE_OPTIONAL_FIELD_USERREFIDX, "UserRefIdx" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_broken_trade_optional_field(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_broken_trade_optional_field, tvb, offset, NSMEQUITIES_ORDERS_BROKEN_TRADE_OPTIONAL_FIELD_SIZE, NSMEQUITIES_ORDERS_BROKEN_TRADE_OPTIONAL_FIELD_ENCODING);

    return offset + NSMEQUITIES_ORDERS_BROKEN_TRADE_OPTIONAL_FIELD_SIZE;
}

/* Broken Trade Reason */
#define NSMEQUITIES_ORDERS_BROKEN_TRADE_REASON_NAME        "Broken Trade Reason"
#define NSMEQUITIES_ORDERS_BROKEN_TRADE_REASON_DESCRIPTION "The reason the trade was broken."
#define NSMEQUITIES_ORDERS_BROKEN_TRADE_REASON_FILTER      "nsmequities.orders.brokentradereason"
#define NSMEQUITIES_ORDERS_BROKEN_TRADE_REASON_TYPE        FT_CHAR
#define NSMEQUITIES_ORDERS_BROKEN_TRADE_REASON_DISPLAY     BASE_HEX
#define NSMEQUITIES_ORDERS_BROKEN_TRADE_REASON_MASK        0x0
#define NSMEQUITIES_ORDERS_BROKEN_TRADE_REASON_ENCODING    ENC_ASCII
#define NSMEQUITIES_ORDERS_BROKEN_TRADE_REASON_SIZE        1

static const value_string nsmequities_orders_broken_trade_reason_vals[] = {
    { 'E', "Erroneous" },
    { 'C', "Consent" },
    { 'S', "Supervisory" },
    { 'X', "External" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_broken_trade_reason(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_broken_trade_reason, tvb, offset, NSMEQUITIES_ORDERS_BROKEN_TRADE_REASON_SIZE, NSMEQUITIES_ORDERS_BROKEN_TRADE_REASON_ENCODING);

    return offset + NSMEQUITIES_ORDERS_BROKEN_TRADE_REASON_SIZE;
}

/* Buy Sell Indicator */
#define NSMEQUITIES_ORDERS_BUY_SELL_INDICATOR_NAME     "Buy Sell Indicator"
#define NSMEQUITIES_ORDERS_BUY_SELL_INDICATOR_FILTER   "nsmequities.orders.buysellindicator"
#define NSMEQUITIES_ORDERS_BUY_SELL_INDICATOR_TYPE     FT_CHAR
#define NSMEQUITIES_ORDERS_BUY_SELL_INDICATOR_DISPLAY  BASE_HEX
#define NSMEQUITIES_ORDERS_BUY_SELL_INDICATOR_MASK     0x0
#define NSMEQUITIES_ORDERS_BUY_SELL_INDICATOR_ENCODING ENC_ASCII
#define NSMEQUITIES_ORDERS_BUY_SELL_INDICATOR_SIZE     1

static const value_string nsmequities_orders_buy_sell_indicator_vals[] = {
    { 'B', "Buy" },
    { 'S', "Sell" },
    { 'T', "Sell Short" },
    { 'E', "Sell Short Exempt" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_buy_sell_indicator(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_buy_sell_indicator, tvb, offset, NSMEQUITIES_ORDERS_BUY_SELL_INDICATOR_SIZE, NSMEQUITIES_ORDERS_BUY_SELL_INDICATOR_ENCODING);

    return offset + NSMEQUITIES_ORDERS_BUY_SELL_INDICATOR_SIZE;
}

/* Cancel Order Optional Field values the dispatch switches on */
#define NSMEQUITIES_ORDERS_CANCEL_ORDER_OPTIONAL_FIELD_USERREFIDX 28

/* Cancel Order Optional Field */
#define NSMEQUITIES_ORDERS_CANCEL_ORDER_OPTIONAL_FIELD_NAME        "Cancel Order Optional Field"
#define NSMEQUITIES_ORDERS_CANCEL_ORDER_OPTIONAL_FIELD_DESCRIPTION "Appendage Id"
#define NSMEQUITIES_ORDERS_CANCEL_ORDER_OPTIONAL_FIELD_FILTER      "nsmequities.orders.cancelorderoptionalfield"
#define NSMEQUITIES_ORDERS_CANCEL_ORDER_OPTIONAL_FIELD_TYPE        FT_UINT8
#define NSMEQUITIES_ORDERS_CANCEL_ORDER_OPTIONAL_FIELD_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_CANCEL_ORDER_OPTIONAL_FIELD_MASK        0x0
#define NSMEQUITIES_ORDERS_CANCEL_ORDER_OPTIONAL_FIELD_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_CANCEL_ORDER_OPTIONAL_FIELD_SIZE        1

static const value_string nsmequities_orders_cancel_order_optional_field_vals[] = {
    { NSMEQUITIES_ORDERS_CANCEL_ORDER_OPTIONAL_FIELD_USERREFIDX, "UserRefIdx" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_cancel_order_optional_field(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_cancel_order_optional_field, tvb, offset, NSMEQUITIES_ORDERS_CANCEL_ORDER_OPTIONAL_FIELD_SIZE, NSMEQUITIES_ORDERS_CANCEL_ORDER_OPTIONAL_FIELD_ENCODING);

    return offset + NSMEQUITIES_ORDERS_CANCEL_ORDER_OPTIONAL_FIELD_SIZE;
}

/* Cancel Order Reason */
#define NSMEQUITIES_ORDERS_CANCEL_ORDER_REASON_NAME        "Cancel Order Reason"
#define NSMEQUITIES_ORDERS_CANCEL_ORDER_REASON_DESCRIPTION "Reason the order was reduced or canceled."
#define NSMEQUITIES_ORDERS_CANCEL_ORDER_REASON_FILTER      "nsmequities.orders.cancelorderreason"
#define NSMEQUITIES_ORDERS_CANCEL_ORDER_REASON_TYPE        FT_CHAR
#define NSMEQUITIES_ORDERS_CANCEL_ORDER_REASON_DISPLAY     BASE_HEX
#define NSMEQUITIES_ORDERS_CANCEL_ORDER_REASON_MASK        0x0
#define NSMEQUITIES_ORDERS_CANCEL_ORDER_REASON_ENCODING    ENC_ASCII
#define NSMEQUITIES_ORDERS_CANCEL_ORDER_REASON_SIZE        1

static const value_string nsmequities_orders_cancel_order_reason_vals[] = {
    { 'U', "User Requested Cancel" },
    { 'I', "Immediate Or Cancel Order" },
    { 'T', "Timeout" },
    { 'S', "Supervisory" },
    { 'D', "Regulatory Restriction" },
    { 'Q', "Self Match Prevention" },
    { 'Z', "System Cancel" },
    { 'K', "This Order Cannot Be Executed" },
    { 'H', "Halted" },
    { 'X', "Open Protection" },
    { 'E', "Closed" },
    { 'F', "Post Only Cancel" },
    { 'G', "Post Only Cancel Contra Side Displayed" },
    { 'e', "Company Direct Listing Capital Raise Order Exceeds Allowable Shares Offered" },
    { 'C', "Cross Canceled" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_cancel_order_reason(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_cancel_order_reason, tvb, offset, NSMEQUITIES_ORDERS_CANCEL_ORDER_REASON_SIZE, NSMEQUITIES_ORDERS_CANCEL_ORDER_REASON_ENCODING);

    return offset + NSMEQUITIES_ORDERS_CANCEL_ORDER_REASON_SIZE;
}

/* Cancel Pending Optional Field values the dispatch switches on */
#define NSMEQUITIES_ORDERS_CANCEL_PENDING_OPTIONAL_FIELD_USERREFIDX 28

/* Cancel Pending Optional Field */
#define NSMEQUITIES_ORDERS_CANCEL_PENDING_OPTIONAL_FIELD_NAME        "Cancel Pending Optional Field"
#define NSMEQUITIES_ORDERS_CANCEL_PENDING_OPTIONAL_FIELD_DESCRIPTION "Appendage Id"
#define NSMEQUITIES_ORDERS_CANCEL_PENDING_OPTIONAL_FIELD_FILTER      "nsmequities.orders.cancelpendingoptionalfield"
#define NSMEQUITIES_ORDERS_CANCEL_PENDING_OPTIONAL_FIELD_TYPE        FT_UINT8
#define NSMEQUITIES_ORDERS_CANCEL_PENDING_OPTIONAL_FIELD_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_CANCEL_PENDING_OPTIONAL_FIELD_MASK        0x0
#define NSMEQUITIES_ORDERS_CANCEL_PENDING_OPTIONAL_FIELD_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_CANCEL_PENDING_OPTIONAL_FIELD_SIZE        1

static const value_string nsmequities_orders_cancel_pending_optional_field_vals[] = {
    { NSMEQUITIES_ORDERS_CANCEL_PENDING_OPTIONAL_FIELD_USERREFIDX, "UserRefIdx" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_cancel_pending_optional_field(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_cancel_pending_optional_field, tvb, offset, NSMEQUITIES_ORDERS_CANCEL_PENDING_OPTIONAL_FIELD_SIZE, NSMEQUITIES_ORDERS_CANCEL_PENDING_OPTIONAL_FIELD_ENCODING);

    return offset + NSMEQUITIES_ORDERS_CANCEL_PENDING_OPTIONAL_FIELD_SIZE;
}

/* Cancel Reject Optional Field values the dispatch switches on */
#define NSMEQUITIES_ORDERS_CANCEL_REJECT_OPTIONAL_FIELD_USERREFIDX 28

/* Cancel Reject Optional Field */
#define NSMEQUITIES_ORDERS_CANCEL_REJECT_OPTIONAL_FIELD_NAME        "Cancel Reject Optional Field"
#define NSMEQUITIES_ORDERS_CANCEL_REJECT_OPTIONAL_FIELD_DESCRIPTION "Appendage Id"
#define NSMEQUITIES_ORDERS_CANCEL_REJECT_OPTIONAL_FIELD_FILTER      "nsmequities.orders.cancelrejectoptionalfield"
#define NSMEQUITIES_ORDERS_CANCEL_REJECT_OPTIONAL_FIELD_TYPE        FT_UINT8
#define NSMEQUITIES_ORDERS_CANCEL_REJECT_OPTIONAL_FIELD_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_CANCEL_REJECT_OPTIONAL_FIELD_MASK        0x0
#define NSMEQUITIES_ORDERS_CANCEL_REJECT_OPTIONAL_FIELD_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_CANCEL_REJECT_OPTIONAL_FIELD_SIZE        1

static const value_string nsmequities_orders_cancel_reject_optional_field_vals[] = {
    { NSMEQUITIES_ORDERS_CANCEL_REJECT_OPTIONAL_FIELD_USERREFIDX, "UserRefIdx" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_cancel_reject_optional_field(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_cancel_reject_optional_field, tvb, offset, NSMEQUITIES_ORDERS_CANCEL_REJECT_OPTIONAL_FIELD_SIZE, NSMEQUITIES_ORDERS_CANCEL_REJECT_OPTIONAL_FIELD_ENCODING);

    return offset + NSMEQUITIES_ORDERS_CANCEL_REJECT_OPTIONAL_FIELD_SIZE;
}

/* Canceled Message Optional Field values the dispatch switches on */
#define NSMEQUITIES_ORDERS_CANCELED_MESSAGE_OPTIONAL_FIELD_USERREFIDX 28

/* Canceled Message Optional Field */
#define NSMEQUITIES_ORDERS_CANCELED_MESSAGE_OPTIONAL_FIELD_NAME        "Canceled Message Optional Field"
#define NSMEQUITIES_ORDERS_CANCELED_MESSAGE_OPTIONAL_FIELD_DESCRIPTION "Appendage Id"
#define NSMEQUITIES_ORDERS_CANCELED_MESSAGE_OPTIONAL_FIELD_FILTER      "nsmequities.orders.canceledmessageoptionalfield"
#define NSMEQUITIES_ORDERS_CANCELED_MESSAGE_OPTIONAL_FIELD_TYPE        FT_UINT8
#define NSMEQUITIES_ORDERS_CANCELED_MESSAGE_OPTIONAL_FIELD_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_CANCELED_MESSAGE_OPTIONAL_FIELD_MASK        0x0
#define NSMEQUITIES_ORDERS_CANCELED_MESSAGE_OPTIONAL_FIELD_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_CANCELED_MESSAGE_OPTIONAL_FIELD_SIZE        1

static const value_string nsmequities_orders_canceled_message_optional_field_vals[] = {
    { NSMEQUITIES_ORDERS_CANCELED_MESSAGE_OPTIONAL_FIELD_USERREFIDX, "UserRefIdx" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_canceled_message_optional_field(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_canceled_message_optional_field, tvb, offset, NSMEQUITIES_ORDERS_CANCELED_MESSAGE_OPTIONAL_FIELD_SIZE, NSMEQUITIES_ORDERS_CANCELED_MESSAGE_OPTIONAL_FIELD_ENCODING);

    return offset + NSMEQUITIES_ORDERS_CANCELED_MESSAGE_OPTIONAL_FIELD_SIZE;
}

/* Capacity */
#define NSMEQUITIES_ORDERS_CAPACITY_NAME     "Capacity"
#define NSMEQUITIES_ORDERS_CAPACITY_FILTER   "nsmequities.orders.capacity"
#define NSMEQUITIES_ORDERS_CAPACITY_TYPE     FT_CHAR
#define NSMEQUITIES_ORDERS_CAPACITY_DISPLAY  BASE_HEX
#define NSMEQUITIES_ORDERS_CAPACITY_MASK     0x0
#define NSMEQUITIES_ORDERS_CAPACITY_ENCODING ENC_ASCII
#define NSMEQUITIES_ORDERS_CAPACITY_SIZE     1

static const value_string nsmequities_orders_capacity_vals[] = {
    { 'O', "Other" },
    { 'A', "Agency" },
    { 'P', "Principal" },
    { 'R', "Riskless" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_capacity(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_capacity, tvb, offset, NSMEQUITIES_ORDERS_CAPACITY_SIZE, NSMEQUITIES_ORDERS_CAPACITY_ENCODING);

    return offset + NSMEQUITIES_ORDERS_CAPACITY_SIZE;
}

/* ClOrdId */
#define NSMEQUITIES_ORDERS_CLORDID_NAME        "ClOrdId"
#define NSMEQUITIES_ORDERS_CLORDID_DESCRIPTION "Customer order identifier. ClOrdID will not be checked for day-uniqueness for each OUCH account."
#define NSMEQUITIES_ORDERS_CLORDID_FILTER      "nsmequities.orders.clordid"
#define NSMEQUITIES_ORDERS_CLORDID_TYPE        FT_STRING
#define NSMEQUITIES_ORDERS_CLORDID_DISPLAY     BASE_NONE
#define NSMEQUITIES_ORDERS_CLORDID_MASK        0x0
#define NSMEQUITIES_ORDERS_CLORDID_ENCODING    ENC_ASCII
#define NSMEQUITIES_ORDERS_CLORDID_SIZE        14

static unsigned
parse_nsmequities_orders_clordid(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_clordid, tvb, offset, NSMEQUITIES_ORDERS_CLORDID_SIZE, NSMEQUITIES_ORDERS_CLORDID_ENCODING);

    return offset + NSMEQUITIES_ORDERS_CLORDID_SIZE;
}

/* Client Packet Type values the dispatch switches on */
#define NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_DEBUG_PACKET            '+'
#define NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_LOGIN_REQUEST_PACKET    'L'
#define NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_UNSEQUENCED_DATA_PACKET 'U'
#define NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_CLIENT_HEARTBEAT_PACKET 'R'
#define NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_LOGOUT_REQUEST_PACKET   'O'

/* Client Packet Type */
#define NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_NAME        "Packet Type"
#define NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_DESCRIPTION "Code identifying this packet type sent by the client"
#define NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_FILTER      "nsmequities.orders.clientpackettype"
#define NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_TYPE        FT_CHAR
#define NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_DISPLAY     BASE_HEX
#define NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_MASK        0x0
#define NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_ENCODING    ENC_ASCII
#define NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_SIZE        1

static const value_string nsmequities_orders_client_packet_type_vals[] = {
    { NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_DEBUG_PACKET, "Debug Packet" },
    { NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_LOGIN_REQUEST_PACKET, "Login Request Packet" },
    { NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_UNSEQUENCED_DATA_PACKET, "Unsequenced Data Packet" },
    { NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_CLIENT_HEARTBEAT_PACKET, "Client Heartbeat Packet" },
    { NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_LOGOUT_REQUEST_PACKET, "Logout Request Packet" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_client_packet_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_client_packet_type, tvb, offset, NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_SIZE, NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_ENCODING);

    return offset + NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_SIZE;
}

/* Cross Type */
#define NSMEQUITIES_ORDERS_CROSS_TYPE_NAME        "Cross Type"
#define NSMEQUITIES_ORDERS_CROSS_TYPE_DESCRIPTION "CrossType"
#define NSMEQUITIES_ORDERS_CROSS_TYPE_FILTER      "nsmequities.orders.crosstype"
#define NSMEQUITIES_ORDERS_CROSS_TYPE_TYPE        FT_CHAR
#define NSMEQUITIES_ORDERS_CROSS_TYPE_DISPLAY     BASE_HEX
#define NSMEQUITIES_ORDERS_CROSS_TYPE_MASK        0x0
#define NSMEQUITIES_ORDERS_CROSS_TYPE_ENCODING    ENC_ASCII
#define NSMEQUITIES_ORDERS_CROSS_TYPE_SIZE        1

static const value_string nsmequities_orders_cross_type_vals[] = {
    { 'N', "Continuous Market" },
    { 'O', "Opening Cross" },
    { 'C', "Closing Cross" },
    { 'H', "Halt Ipo" },
    { 'S', "Supplemental" },
    { 'R', "Retail" },
    { 'E', "Extended Life" },
    { 'A', "After Hours Close" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_cross_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_cross_type, tvb, offset, NSMEQUITIES_ORDERS_CROSS_TYPE_SIZE, NSMEQUITIES_ORDERS_CROSS_TYPE_ENCODING);

    return offset + NSMEQUITIES_ORDERS_CROSS_TYPE_SIZE;
}

/* Customer Type */
#define NSMEQUITIES_ORDERS_CUSTOMER_TYPE_NAME        "Customer Type"
#define NSMEQUITIES_ORDERS_CUSTOMER_TYPE_DESCRIPTION "CustomerType"
#define NSMEQUITIES_ORDERS_CUSTOMER_TYPE_FILTER      "nsmequities.orders.customertype"
#define NSMEQUITIES_ORDERS_CUSTOMER_TYPE_TYPE        FT_CHAR
#define NSMEQUITIES_ORDERS_CUSTOMER_TYPE_DISPLAY     BASE_HEX
#define NSMEQUITIES_ORDERS_CUSTOMER_TYPE_MASK        0x0
#define NSMEQUITIES_ORDERS_CUSTOMER_TYPE_ENCODING    ENC_ASCII
#define NSMEQUITIES_ORDERS_CUSTOMER_TYPE_SIZE        1

static const value_string nsmequities_orders_customer_type_vals[] = {
    { 'R', "Retail Designated Order" },
    { 'N', "Not Retail Designated" },
    { ' ', "Default" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_customer_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_customer_type, tvb, offset, NSMEQUITIES_ORDERS_CUSTOMER_TYPE_SIZE, NSMEQUITIES_ORDERS_CUSTOMER_TYPE_ENCODING);

    return offset + NSMEQUITIES_ORDERS_CUSTOMER_TYPE_SIZE;
}

/* Customer Type V422018 */
#define NSMEQUITIES_ORDERS_CUSTOMER_TYPE_V422018_NAME        "Customer Type"
#define NSMEQUITIES_ORDERS_CUSTOMER_TYPE_V422018_DESCRIPTION "Indicates if the order is a retail designated order (optional field)"
#define NSMEQUITIES_ORDERS_CUSTOMER_TYPE_V422018_FILTER      "nsmequities.orders.customertype"
#define NSMEQUITIES_ORDERS_CUSTOMER_TYPE_V422018_TYPE        FT_CHAR
#define NSMEQUITIES_ORDERS_CUSTOMER_TYPE_V422018_DISPLAY     BASE_HEX
#define NSMEQUITIES_ORDERS_CUSTOMER_TYPE_V422018_MASK        0x0
#define NSMEQUITIES_ORDERS_CUSTOMER_TYPE_V422018_ENCODING    ENC_ASCII
#define NSMEQUITIES_ORDERS_CUSTOMER_TYPE_V422018_SIZE        1

static const value_string nsmequities_orders_customer_type_v422018_vals[] = {
    { 'R', "Retail Designated Order" },
    { 'N', "Not Retail Designated" },
    { ' ', "Default" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_customer_type_v422018(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_customer_type_v422018, tvb, offset, NSMEQUITIES_ORDERS_CUSTOMER_TYPE_V422018_SIZE, NSMEQUITIES_ORDERS_CUSTOMER_TYPE_V422018_ENCODING);

    return offset + NSMEQUITIES_ORDERS_CUSTOMER_TYPE_V422018_SIZE;
}

/* Debug Text */
#define NSMEQUITIES_ORDERS_DEBUG_TEXT_NAME        "Debug Text"
#define NSMEQUITIES_ORDERS_DEBUG_TEXT_DESCRIPTION "Free form human readable text"
#define NSMEQUITIES_ORDERS_DEBUG_TEXT_FILTER      "nsmequities.orders.debugtext"
#define NSMEQUITIES_ORDERS_DEBUG_TEXT_TYPE        FT_STRING
#define NSMEQUITIES_ORDERS_DEBUG_TEXT_DISPLAY     BASE_NONE
#define NSMEQUITIES_ORDERS_DEBUG_TEXT_MASK        0x0
#define NSMEQUITIES_ORDERS_DEBUG_TEXT_ENCODING    ENC_NA

/* Decrement Shares */
#define NSMEQUITIES_ORDERS_DECREMENT_SHARES_NAME        "Decrement Shares"
#define NSMEQUITIES_ORDERS_DECREMENT_SHARES_DESCRIPTION "The number of shares just decremented from the order. This number is incremental, not cumulative."
#define NSMEQUITIES_ORDERS_DECREMENT_SHARES_FILTER      "nsmequities.orders.decrementshares"
#define NSMEQUITIES_ORDERS_DECREMENT_SHARES_TYPE        FT_UINT32
#define NSMEQUITIES_ORDERS_DECREMENT_SHARES_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_DECREMENT_SHARES_MASK        0x0
#define NSMEQUITIES_ORDERS_DECREMENT_SHARES_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_DECREMENT_SHARES_SIZE        4

static unsigned
parse_nsmequities_orders_decrement_shares(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_decrement_shares, tvb, offset, NSMEQUITIES_ORDERS_DECREMENT_SHARES_SIZE, NSMEQUITIES_ORDERS_DECREMENT_SHARES_ENCODING);

    return offset + NSMEQUITIES_ORDERS_DECREMENT_SHARES_SIZE;
}

/* Disable Order Entry Request Optional Field values the dispatch switches on */
#define NSMEQUITIES_ORDERS_DISABLE_ORDER_ENTRY_REQUEST_OPTIONAL_FIELD_USERREFIDX 28

/* Disable Order Entry Request Optional Field */
#define NSMEQUITIES_ORDERS_DISABLE_ORDER_ENTRY_REQUEST_OPTIONAL_FIELD_NAME        "Disable Order Entry Request Optional Field"
#define NSMEQUITIES_ORDERS_DISABLE_ORDER_ENTRY_REQUEST_OPTIONAL_FIELD_DESCRIPTION "Appendage Id"
#define NSMEQUITIES_ORDERS_DISABLE_ORDER_ENTRY_REQUEST_OPTIONAL_FIELD_FILTER      "nsmequities.orders.disableorderentryrequestoptionalfield"
#define NSMEQUITIES_ORDERS_DISABLE_ORDER_ENTRY_REQUEST_OPTIONAL_FIELD_TYPE        FT_UINT8
#define NSMEQUITIES_ORDERS_DISABLE_ORDER_ENTRY_REQUEST_OPTIONAL_FIELD_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_DISABLE_ORDER_ENTRY_REQUEST_OPTIONAL_FIELD_MASK        0x0
#define NSMEQUITIES_ORDERS_DISABLE_ORDER_ENTRY_REQUEST_OPTIONAL_FIELD_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_DISABLE_ORDER_ENTRY_REQUEST_OPTIONAL_FIELD_SIZE        1

static const value_string nsmequities_orders_disable_order_entry_request_optional_field_vals[] = {
    { NSMEQUITIES_ORDERS_DISABLE_ORDER_ENTRY_REQUEST_OPTIONAL_FIELD_USERREFIDX, "UserRefIdx" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_disable_order_entry_request_optional_field(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_disable_order_entry_request_optional_field, tvb, offset, NSMEQUITIES_ORDERS_DISABLE_ORDER_ENTRY_REQUEST_OPTIONAL_FIELD_SIZE, NSMEQUITIES_ORDERS_DISABLE_ORDER_ENTRY_REQUEST_OPTIONAL_FIELD_ENCODING);

    return offset + NSMEQUITIES_ORDERS_DISABLE_ORDER_ENTRY_REQUEST_OPTIONAL_FIELD_SIZE;
}

/* Disable Order Entry Response Optional Field values the dispatch switches on */
#define NSMEQUITIES_ORDERS_DISABLE_ORDER_ENTRY_RESPONSE_OPTIONAL_FIELD_USERREFIDX 28

/* Disable Order Entry Response Optional Field */
#define NSMEQUITIES_ORDERS_DISABLE_ORDER_ENTRY_RESPONSE_OPTIONAL_FIELD_NAME        "Disable Order Entry Response Optional Field"
#define NSMEQUITIES_ORDERS_DISABLE_ORDER_ENTRY_RESPONSE_OPTIONAL_FIELD_DESCRIPTION "Appendage Id"
#define NSMEQUITIES_ORDERS_DISABLE_ORDER_ENTRY_RESPONSE_OPTIONAL_FIELD_FILTER      "nsmequities.orders.disableorderentryresponseoptionalfield"
#define NSMEQUITIES_ORDERS_DISABLE_ORDER_ENTRY_RESPONSE_OPTIONAL_FIELD_TYPE        FT_UINT8
#define NSMEQUITIES_ORDERS_DISABLE_ORDER_ENTRY_RESPONSE_OPTIONAL_FIELD_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_DISABLE_ORDER_ENTRY_RESPONSE_OPTIONAL_FIELD_MASK        0x0
#define NSMEQUITIES_ORDERS_DISABLE_ORDER_ENTRY_RESPONSE_OPTIONAL_FIELD_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_DISABLE_ORDER_ENTRY_RESPONSE_OPTIONAL_FIELD_SIZE        1

static const value_string nsmequities_orders_disable_order_entry_response_optional_field_vals[] = {
    { NSMEQUITIES_ORDERS_DISABLE_ORDER_ENTRY_RESPONSE_OPTIONAL_FIELD_USERREFIDX, "UserRefIdx" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_disable_order_entry_response_optional_field(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_disable_order_entry_response_optional_field, tvb, offset, NSMEQUITIES_ORDERS_DISABLE_ORDER_ENTRY_RESPONSE_OPTIONAL_FIELD_SIZE, NSMEQUITIES_ORDERS_DISABLE_ORDER_ENTRY_RESPONSE_OPTIONAL_FIELD_ENCODING);

    return offset + NSMEQUITIES_ORDERS_DISABLE_ORDER_ENTRY_RESPONSE_OPTIONAL_FIELD_SIZE;
}

/* Discretion Peg Offset */
#define NSMEQUITIES_ORDERS_DISCRETION_PEG_OFFSET_NAME        "Discretion Peg Offset"
#define NSMEQUITIES_ORDERS_DISCRETION_PEG_OFFSET_DESCRIPTION "Offset amount for the pegged value of the Discretionary Price."
#define NSMEQUITIES_ORDERS_DISCRETION_PEG_OFFSET_FILTER      "nsmequities.orders.discretionpegoffset"
#define NSMEQUITIES_ORDERS_DISCRETION_PEG_OFFSET_TYPE        FT_INT32
#define NSMEQUITIES_ORDERS_DISCRETION_PEG_OFFSET_DISPLAY     BASE_CUSTOM
#define NSMEQUITIES_ORDERS_DISCRETION_PEG_OFFSET_MASK        0x0
#define NSMEQUITIES_ORDERS_DISCRETION_PEG_OFFSET_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_DISCRETION_PEG_OFFSET_SIZE        4

static unsigned
parse_nsmequities_orders_discretion_peg_offset(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_discretion_peg_offset, tvb, offset, NSMEQUITIES_ORDERS_DISCRETION_PEG_OFFSET_SIZE, NSMEQUITIES_ORDERS_DISCRETION_PEG_OFFSET_ENCODING);

    return offset + NSMEQUITIES_ORDERS_DISCRETION_PEG_OFFSET_SIZE;
}

/* Discretion Price */
#define NSMEQUITIES_ORDERS_DISCRETION_PRICE_NAME        "Discretion Price"
#define NSMEQUITIES_ORDERS_DISCRETION_PRICE_DESCRIPTION "Discretion price for Discretionary Order."
#define NSMEQUITIES_ORDERS_DISCRETION_PRICE_FILTER      "nsmequities.orders.discretionprice"
#define NSMEQUITIES_ORDERS_DISCRETION_PRICE_TYPE        FT_UINT64
#define NSMEQUITIES_ORDERS_DISCRETION_PRICE_DISPLAY     BASE_CUSTOM
#define NSMEQUITIES_ORDERS_DISCRETION_PRICE_MASK        0x0
#define NSMEQUITIES_ORDERS_DISCRETION_PRICE_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_DISCRETION_PRICE_SIZE        8

static unsigned
parse_nsmequities_orders_discretion_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_discretion_price, tvb, offset, NSMEQUITIES_ORDERS_DISCRETION_PRICE_SIZE, NSMEQUITIES_ORDERS_DISCRETION_PRICE_ENCODING);

    return offset + NSMEQUITIES_ORDERS_DISCRETION_PRICE_SIZE;
}

/* Discretion Price Type */
#define NSMEQUITIES_ORDERS_DISCRETION_PRICE_TYPE_NAME        "Discretion Price Type"
#define NSMEQUITIES_ORDERS_DISCRETION_PRICE_TYPE_DESCRIPTION "DiscretionPriceType"
#define NSMEQUITIES_ORDERS_DISCRETION_PRICE_TYPE_FILTER      "nsmequities.orders.discretionpricetype"
#define NSMEQUITIES_ORDERS_DISCRETION_PRICE_TYPE_TYPE        FT_CHAR
#define NSMEQUITIES_ORDERS_DISCRETION_PRICE_TYPE_DISPLAY     BASE_HEX
#define NSMEQUITIES_ORDERS_DISCRETION_PRICE_TYPE_MASK        0x0
#define NSMEQUITIES_ORDERS_DISCRETION_PRICE_TYPE_ENCODING    ENC_ASCII
#define NSMEQUITIES_ORDERS_DISCRETION_PRICE_TYPE_SIZE        1

static const value_string nsmequities_orders_discretion_price_type_vals[] = {
    { 'L', "Limit" },
    { 'P', "Market Peg" },
    { 'M', "Midpoint Peg" },
    { 'R', "Primary Peg" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_discretion_price_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_discretion_price_type, tvb, offset, NSMEQUITIES_ORDERS_DISCRETION_PRICE_TYPE_SIZE, NSMEQUITIES_ORDERS_DISCRETION_PRICE_TYPE_ENCODING);

    return offset + NSMEQUITIES_ORDERS_DISCRETION_PRICE_TYPE_SIZE;
}

/* Display */
#define NSMEQUITIES_ORDERS_DISPLAY_NAME     "Display"
#define NSMEQUITIES_ORDERS_DISPLAY_FILTER   "nsmequities.orders.display"
#define NSMEQUITIES_ORDERS_DISPLAY_TYPE     FT_CHAR
#define NSMEQUITIES_ORDERS_DISPLAY_DISPLAY  BASE_HEX
#define NSMEQUITIES_ORDERS_DISPLAY_MASK     0x0
#define NSMEQUITIES_ORDERS_DISPLAY_ENCODING ENC_ASCII
#define NSMEQUITIES_ORDERS_DISPLAY_SIZE     1

static const value_string nsmequities_orders_display_vals[] = {
    { 'A', "Attributable" },
    { 'Y', "Visible" },
    { 'N', "Hidden" },
    { 'Z', "Conformant" },
    { 'P', "Post Only" },
    { 'I', "Imbalance Only" },
    { 'M', "Mid Point Peg" },
    { 'W', "Mid Point Peg Post Only" },
    { 'L', "Post Only And Attributable" },
    { 'O', "Retail Order Type 1" },
    { 'T', "Retail Order Type 2" },
    { 'Q', "Retail Price" },
    { 'm', "Mid Point Peg And Mid Point Trade Now" },
    { 'n', "Non Display And Mid Point" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_display(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_display, tvb, offset, NSMEQUITIES_ORDERS_DISPLAY_SIZE, NSMEQUITIES_ORDERS_DISPLAY_ENCODING);

    return offset + NSMEQUITIES_ORDERS_DISPLAY_SIZE;
}

/* Display Price */
#define NSMEQUITIES_ORDERS_DISPLAY_PRICE_NAME        "Display Price"
#define NSMEQUITIES_ORDERS_DISPLAY_PRICE_DESCRIPTION "Used in the Order Restated Message only. Represents an update of an order's displayed price."
#define NSMEQUITIES_ORDERS_DISPLAY_PRICE_FILTER      "nsmequities.orders.displayprice"
#define NSMEQUITIES_ORDERS_DISPLAY_PRICE_TYPE        FT_UINT64
#define NSMEQUITIES_ORDERS_DISPLAY_PRICE_DISPLAY     BASE_CUSTOM
#define NSMEQUITIES_ORDERS_DISPLAY_PRICE_MASK        0x0
#define NSMEQUITIES_ORDERS_DISPLAY_PRICE_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_DISPLAY_PRICE_SIZE        8

static unsigned
parse_nsmequities_orders_display_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_display_price, tvb, offset, NSMEQUITIES_ORDERS_DISPLAY_PRICE_SIZE, NSMEQUITIES_ORDERS_DISPLAY_PRICE_ENCODING);

    return offset + NSMEQUITIES_ORDERS_DISPLAY_PRICE_SIZE;
}

/* Display Quantity */
#define NSMEQUITIES_ORDERS_DISPLAY_QUANTITY_NAME        "Display Quantity"
#define NSMEQUITIES_ORDERS_DISPLAY_QUANTITY_DESCRIPTION "Used in the Order Restated Message only. Represents an update of an order's displayed quantity (i.e. an order with reserves)."
#define NSMEQUITIES_ORDERS_DISPLAY_QUANTITY_FILTER      "nsmequities.orders.displayquantity"
#define NSMEQUITIES_ORDERS_DISPLAY_QUANTITY_TYPE        FT_UINT32
#define NSMEQUITIES_ORDERS_DISPLAY_QUANTITY_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_DISPLAY_QUANTITY_MASK        0x0
#define NSMEQUITIES_ORDERS_DISPLAY_QUANTITY_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_DISPLAY_QUANTITY_SIZE        4

static unsigned
parse_nsmequities_orders_display_quantity(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_display_quantity, tvb, offset, NSMEQUITIES_ORDERS_DISPLAY_QUANTITY_SIZE, NSMEQUITIES_ORDERS_DISPLAY_QUANTITY_ENCODING);

    return offset + NSMEQUITIES_ORDERS_DISPLAY_QUANTITY_SIZE;
}

/* Enable Order Entry Request Optional Field values the dispatch switches on */
#define NSMEQUITIES_ORDERS_ENABLE_ORDER_ENTRY_REQUEST_OPTIONAL_FIELD_USERREFIDX 28

/* Enable Order Entry Request Optional Field */
#define NSMEQUITIES_ORDERS_ENABLE_ORDER_ENTRY_REQUEST_OPTIONAL_FIELD_NAME        "Enable Order Entry Request Optional Field"
#define NSMEQUITIES_ORDERS_ENABLE_ORDER_ENTRY_REQUEST_OPTIONAL_FIELD_DESCRIPTION "Appendage Id"
#define NSMEQUITIES_ORDERS_ENABLE_ORDER_ENTRY_REQUEST_OPTIONAL_FIELD_FILTER      "nsmequities.orders.enableorderentryrequestoptionalfield"
#define NSMEQUITIES_ORDERS_ENABLE_ORDER_ENTRY_REQUEST_OPTIONAL_FIELD_TYPE        FT_UINT8
#define NSMEQUITIES_ORDERS_ENABLE_ORDER_ENTRY_REQUEST_OPTIONAL_FIELD_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_ENABLE_ORDER_ENTRY_REQUEST_OPTIONAL_FIELD_MASK        0x0
#define NSMEQUITIES_ORDERS_ENABLE_ORDER_ENTRY_REQUEST_OPTIONAL_FIELD_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_ENABLE_ORDER_ENTRY_REQUEST_OPTIONAL_FIELD_SIZE        1

static const value_string nsmequities_orders_enable_order_entry_request_optional_field_vals[] = {
    { NSMEQUITIES_ORDERS_ENABLE_ORDER_ENTRY_REQUEST_OPTIONAL_FIELD_USERREFIDX, "UserRefIdx" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_enable_order_entry_request_optional_field(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_enable_order_entry_request_optional_field, tvb, offset, NSMEQUITIES_ORDERS_ENABLE_ORDER_ENTRY_REQUEST_OPTIONAL_FIELD_SIZE, NSMEQUITIES_ORDERS_ENABLE_ORDER_ENTRY_REQUEST_OPTIONAL_FIELD_ENCODING);

    return offset + NSMEQUITIES_ORDERS_ENABLE_ORDER_ENTRY_REQUEST_OPTIONAL_FIELD_SIZE;
}

/* Enable Order Entry Response Optional Field values the dispatch switches on */
#define NSMEQUITIES_ORDERS_ENABLE_ORDER_ENTRY_RESPONSE_OPTIONAL_FIELD_USERREFIDX 28

/* Enable Order Entry Response Optional Field */
#define NSMEQUITIES_ORDERS_ENABLE_ORDER_ENTRY_RESPONSE_OPTIONAL_FIELD_NAME        "Enable Order Entry Response Optional Field"
#define NSMEQUITIES_ORDERS_ENABLE_ORDER_ENTRY_RESPONSE_OPTIONAL_FIELD_DESCRIPTION "Appendage Id"
#define NSMEQUITIES_ORDERS_ENABLE_ORDER_ENTRY_RESPONSE_OPTIONAL_FIELD_FILTER      "nsmequities.orders.enableorderentryresponseoptionalfield"
#define NSMEQUITIES_ORDERS_ENABLE_ORDER_ENTRY_RESPONSE_OPTIONAL_FIELD_TYPE        FT_UINT8
#define NSMEQUITIES_ORDERS_ENABLE_ORDER_ENTRY_RESPONSE_OPTIONAL_FIELD_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_ENABLE_ORDER_ENTRY_RESPONSE_OPTIONAL_FIELD_MASK        0x0
#define NSMEQUITIES_ORDERS_ENABLE_ORDER_ENTRY_RESPONSE_OPTIONAL_FIELD_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_ENABLE_ORDER_ENTRY_RESPONSE_OPTIONAL_FIELD_SIZE        1

static const value_string nsmequities_orders_enable_order_entry_response_optional_field_vals[] = {
    { NSMEQUITIES_ORDERS_ENABLE_ORDER_ENTRY_RESPONSE_OPTIONAL_FIELD_USERREFIDX, "UserRefIdx" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_enable_order_entry_response_optional_field(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_enable_order_entry_response_optional_field, tvb, offset, NSMEQUITIES_ORDERS_ENABLE_ORDER_ENTRY_RESPONSE_OPTIONAL_FIELD_SIZE, NSMEQUITIES_ORDERS_ENABLE_ORDER_ENTRY_RESPONSE_OPTIONAL_FIELD_ENCODING);

    return offset + NSMEQUITIES_ORDERS_ENABLE_ORDER_ENTRY_RESPONSE_OPTIONAL_FIELD_SIZE;
}

/* Enter Order Optional Field values the dispatch switches on */
#define NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_FIRM                2
#define NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_MINQTY              3
#define NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_CUSTOMERTYPE        4
#define NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_MAXFLOOR            5
#define NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_PRICETYPE           6
#define NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_PEGOFFSET           7
#define NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_DISCRETIONPRICE     9
#define NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_DISCRETIONPRICETYPE 10
#define NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_DISCRETIONPEGOFFSET 11
#define NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_POSTONLY            12
#define NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_RANDOMRESERVES      13
#define NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_EXPIRETIME          15
#define NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_TRADENOW            16
#define NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_HANDLEINST          17
#define NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_GROUP_ID            24
#define NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_SHARES_LOCATED      25
#define NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_LOCATE_BROKER       26
#define NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_USERREFIDX          28
#define NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_AIQ_STRATEGY        29
#define NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_AIQ_GROUP_ID        30

/* Enter Order Optional Field */
#define NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_NAME        "Enter Order Optional Field"
#define NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_DESCRIPTION "Appendage Id"
#define NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_FILTER      "nsmequities.orders.enterorderoptionalfield"
#define NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_TYPE        FT_UINT8
#define NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_MASK        0x0
#define NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_SIZE        1

static const value_string nsmequities_orders_enter_order_optional_field_vals[] = {
    { NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_FIRM, "Firm" },
    { NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_MINQTY, "MinQty" },
    { NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_CUSTOMERTYPE, "CustomerType" },
    { NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_MAXFLOOR, "MaxFloor" },
    { NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_PRICETYPE, "PriceType" },
    { NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_PEGOFFSET, "PegOffset" },
    { NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_DISCRETIONPRICE, "DiscretionPrice" },
    { NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_DISCRETIONPRICETYPE, "DiscretionPriceType" },
    { NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_DISCRETIONPEGOFFSET, "DiscretionPegOffset" },
    { NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_POSTONLY, "PostOnly" },
    { NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_RANDOMRESERVES, "RandomReserves" },
    { NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_EXPIRETIME, "ExpireTime" },
    { NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_TRADENOW, "TradeNow" },
    { NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_HANDLEINST, "HandleInst" },
    { NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_GROUP_ID, "Group ID" },
    { NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_SHARES_LOCATED, "Shares Located" },
    { NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_LOCATE_BROKER, "Locate Broker" },
    { NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_USERREFIDX, "UserRefIdx" },
    { NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_AIQ_STRATEGY, "AIQ Strategy" },
    { NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_AIQ_GROUP_ID, "AIQ Group ID" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_enter_order_optional_field(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_enter_order_optional_field, tvb, offset, NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_SIZE, NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_ENCODING);

    return offset + NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_SIZE;
}

/* Event Code */
#define NSMEQUITIES_ORDERS_EVENT_CODE_NAME     "Event Code"
#define NSMEQUITIES_ORDERS_EVENT_CODE_FILTER   "nsmequities.orders.eventcode"
#define NSMEQUITIES_ORDERS_EVENT_CODE_TYPE     FT_CHAR
#define NSMEQUITIES_ORDERS_EVENT_CODE_DISPLAY  BASE_HEX
#define NSMEQUITIES_ORDERS_EVENT_CODE_MASK     0x0
#define NSMEQUITIES_ORDERS_EVENT_CODE_ENCODING ENC_ASCII
#define NSMEQUITIES_ORDERS_EVENT_CODE_SIZE     1

static const value_string nsmequities_orders_event_code_vals[] = {
    { 'S', "Start Of Day" },
    { 'E', "End Of Day" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_event_code(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_event_code, tvb, offset, NSMEQUITIES_ORDERS_EVENT_CODE_SIZE, NSMEQUITIES_ORDERS_EVENT_CODE_ENCODING);

    return offset + NSMEQUITIES_ORDERS_EVENT_CODE_SIZE;
}

/* Executed Shares */
#define NSMEQUITIES_ORDERS_EXECUTED_SHARES_NAME        "Executed Shares"
#define NSMEQUITIES_ORDERS_EXECUTED_SHARES_DESCRIPTION "Incremental number of shares executed"
#define NSMEQUITIES_ORDERS_EXECUTED_SHARES_FILTER      "nsmequities.orders.executedshares"
#define NSMEQUITIES_ORDERS_EXECUTED_SHARES_TYPE        FT_UINT32
#define NSMEQUITIES_ORDERS_EXECUTED_SHARES_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_EXECUTED_SHARES_MASK        0x0
#define NSMEQUITIES_ORDERS_EXECUTED_SHARES_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_EXECUTED_SHARES_SIZE        4

static unsigned
parse_nsmequities_orders_executed_shares(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_executed_shares, tvb, offset, NSMEQUITIES_ORDERS_EXECUTED_SHARES_SIZE, NSMEQUITIES_ORDERS_EXECUTED_SHARES_ENCODING);

    return offset + NSMEQUITIES_ORDERS_EXECUTED_SHARES_SIZE;
}

/* Execution Price */
#define NSMEQUITIES_ORDERS_EXECUTION_PRICE_NAME        "Execution Price"
#define NSMEQUITIES_ORDERS_EXECUTION_PRICE_DESCRIPTION "Price at which the trade would have occurred"
#define NSMEQUITIES_ORDERS_EXECUTION_PRICE_FILTER      "nsmequities.orders.executionprice"
#define NSMEQUITIES_ORDERS_EXECUTION_PRICE_TYPE        FT_UINT64
#define NSMEQUITIES_ORDERS_EXECUTION_PRICE_DISPLAY     BASE_CUSTOM
#define NSMEQUITIES_ORDERS_EXECUTION_PRICE_MASK        0x0
#define NSMEQUITIES_ORDERS_EXECUTION_PRICE_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_EXECUTION_PRICE_SIZE        8

static unsigned
parse_nsmequities_orders_execution_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_execution_price, tvb, offset, NSMEQUITIES_ORDERS_EXECUTION_PRICE_SIZE, NSMEQUITIES_ORDERS_EXECUTION_PRICE_ENCODING);

    return offset + NSMEQUITIES_ORDERS_EXECUTION_PRICE_SIZE;
}

/* Execution Price V422018 */
#define NSMEQUITIES_ORDERS_EXECUTION_PRICE_V422018_NAME        "Execution Price"
#define NSMEQUITIES_ORDERS_EXECUTION_PRICE_V422018_DESCRIPTION "Price at which the trade would have occurred"
#define NSMEQUITIES_ORDERS_EXECUTION_PRICE_V422018_FILTER      "nsmequities.orders.executionprice"
#define NSMEQUITIES_ORDERS_EXECUTION_PRICE_V422018_TYPE        FT_UINT32
#define NSMEQUITIES_ORDERS_EXECUTION_PRICE_V422018_DISPLAY     BASE_CUSTOM
#define NSMEQUITIES_ORDERS_EXECUTION_PRICE_V422018_MASK        0x0
#define NSMEQUITIES_ORDERS_EXECUTION_PRICE_V422018_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_EXECUTION_PRICE_V422018_SIZE        4

static unsigned
parse_nsmequities_orders_execution_price_v422018(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_execution_price_v422018, tvb, offset, NSMEQUITIES_ORDERS_EXECUTION_PRICE_V422018_SIZE, NSMEQUITIES_ORDERS_EXECUTION_PRICE_V422018_ENCODING);

    return offset + NSMEQUITIES_ORDERS_EXECUTION_PRICE_V422018_SIZE;
}

/* Existing Order Token */
#define NSMEQUITIES_ORDERS_EXISTING_ORDER_TOKEN_NAME        "Existing Order Token"
#define NSMEQUITIES_ORDERS_EXISTING_ORDER_TOKEN_DESCRIPTION "This must be filled out with the exact Order Token sent on the Enter Order Message or last Replace Order Message."
#define NSMEQUITIES_ORDERS_EXISTING_ORDER_TOKEN_FILTER      "nsmequities.orders.existingordertoken"
#define NSMEQUITIES_ORDERS_EXISTING_ORDER_TOKEN_TYPE        FT_STRING
#define NSMEQUITIES_ORDERS_EXISTING_ORDER_TOKEN_DISPLAY     BASE_NONE
#define NSMEQUITIES_ORDERS_EXISTING_ORDER_TOKEN_MASK        0x0
#define NSMEQUITIES_ORDERS_EXISTING_ORDER_TOKEN_ENCODING    ENC_ASCII
#define NSMEQUITIES_ORDERS_EXISTING_ORDER_TOKEN_SIZE        14

static unsigned
parse_nsmequities_orders_existing_order_token(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_existing_order_token, tvb, offset, NSMEQUITIES_ORDERS_EXISTING_ORDER_TOKEN_SIZE, NSMEQUITIES_ORDERS_EXISTING_ORDER_TOKEN_ENCODING);

    return offset + NSMEQUITIES_ORDERS_EXISTING_ORDER_TOKEN_SIZE;
}

/* Expire Time */
#define NSMEQUITIES_ORDERS_EXPIRE_TIME_NAME        "Expire Time"
#define NSMEQUITIES_ORDERS_EXPIRE_TIME_DESCRIPTION "Seconds to live. Must be less than 86400 (number of seconds in a day)"
#define NSMEQUITIES_ORDERS_EXPIRE_TIME_FILTER      "nsmequities.orders.expiretime"
#define NSMEQUITIES_ORDERS_EXPIRE_TIME_TYPE        FT_UINT32
#define NSMEQUITIES_ORDERS_EXPIRE_TIME_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_EXPIRE_TIME_MASK        0x0
#define NSMEQUITIES_ORDERS_EXPIRE_TIME_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_EXPIRE_TIME_SIZE        4

static unsigned
parse_nsmequities_orders_expire_time(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_expire_time, tvb, offset, NSMEQUITIES_ORDERS_EXPIRE_TIME_SIZE, NSMEQUITIES_ORDERS_EXPIRE_TIME_ENCODING);

    return offset + NSMEQUITIES_ORDERS_EXPIRE_TIME_SIZE;
}

/* Firm */
#define NSMEQUITIES_ORDERS_FIRM_NAME        "Firm"
#define NSMEQUITIES_ORDERS_FIRM_DESCRIPTION "This field should contain all caps. Firm identifier for the order entry firm. One logical OUCH account can potentially enter orders for multiple firms in a Service Bureau configuration."
#define NSMEQUITIES_ORDERS_FIRM_FILTER      "nsmequities.orders.firm"
#define NSMEQUITIES_ORDERS_FIRM_TYPE        FT_STRING
#define NSMEQUITIES_ORDERS_FIRM_DISPLAY     BASE_NONE
#define NSMEQUITIES_ORDERS_FIRM_MASK        0x0
#define NSMEQUITIES_ORDERS_FIRM_ENCODING    ENC_ASCII
#define NSMEQUITIES_ORDERS_FIRM_SIZE        4

static unsigned
parse_nsmequities_orders_firm(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_firm, tvb, offset, NSMEQUITIES_ORDERS_FIRM_SIZE, NSMEQUITIES_ORDERS_FIRM_ENCODING);

    return offset + NSMEQUITIES_ORDERS_FIRM_SIZE;
}

/* Group Id */
#define NSMEQUITIES_ORDERS_GROUP_ID_NAME        "Group Id"
#define NSMEQUITIES_ORDERS_GROUP_ID_DESCRIPTION "Customer Group ID – identifies specific entity"
#define NSMEQUITIES_ORDERS_GROUP_ID_FILTER      "nsmequities.orders.groupid"
#define NSMEQUITIES_ORDERS_GROUP_ID_TYPE        FT_UINT16
#define NSMEQUITIES_ORDERS_GROUP_ID_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_GROUP_ID_MASK        0x0
#define NSMEQUITIES_ORDERS_GROUP_ID_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_GROUP_ID_SIZE        2

static unsigned
parse_nsmequities_orders_group_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_group_id, tvb, offset, NSMEQUITIES_ORDERS_GROUP_ID_SIZE, NSMEQUITIES_ORDERS_GROUP_ID_ENCODING);

    return offset + NSMEQUITIES_ORDERS_GROUP_ID_SIZE;
}

/* Handle Inst */
#define NSMEQUITIES_ORDERS_HANDLE_INST_NAME        "Handle Inst"
#define NSMEQUITIES_ORDERS_HANDLE_INST_DESCRIPTION "HandleInst"
#define NSMEQUITIES_ORDERS_HANDLE_INST_FILTER      "nsmequities.orders.handleinst"
#define NSMEQUITIES_ORDERS_HANDLE_INST_TYPE        FT_CHAR
#define NSMEQUITIES_ORDERS_HANDLE_INST_DISPLAY     BASE_HEX
#define NSMEQUITIES_ORDERS_HANDLE_INST_MASK        0x0
#define NSMEQUITIES_ORDERS_HANDLE_INST_ENCODING    ENC_ASCII
#define NSMEQUITIES_ORDERS_HANDLE_INST_SIZE        1

static const value_string nsmequities_orders_handle_inst_vals[] = {
    { 'I', "Imbalance Only" },
    { 'O', "Retail Order Type 1" },
    { 'T', "Retail Order Type 2" },
    { 'Q', "Retail Price Improvement" },
    { 'B', "Extended Life Continuous" },
    { 'D', "Direct Listing Capital Raise" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_handle_inst(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_handle_inst, tvb, offset, NSMEQUITIES_ORDERS_HANDLE_INST_SIZE, NSMEQUITIES_ORDERS_HANDLE_INST_ENCODING);

    return offset + NSMEQUITIES_ORDERS_HANDLE_INST_SIZE;
}

/* Inter Market Sweep Eligibility */
#define NSMEQUITIES_ORDERS_INTER_MARKET_SWEEP_ELIGIBILITY_NAME        "Inter Market Sweep Eligibility"
#define NSMEQUITIES_ORDERS_INTER_MARKET_SWEEP_ELIGIBILITY_DESCRIPTION "InterMarket Sweep Eligibility"
#define NSMEQUITIES_ORDERS_INTER_MARKET_SWEEP_ELIGIBILITY_FILTER      "nsmequities.orders.intermarketsweepeligibility"
#define NSMEQUITIES_ORDERS_INTER_MARKET_SWEEP_ELIGIBILITY_TYPE        FT_CHAR
#define NSMEQUITIES_ORDERS_INTER_MARKET_SWEEP_ELIGIBILITY_DISPLAY     BASE_HEX
#define NSMEQUITIES_ORDERS_INTER_MARKET_SWEEP_ELIGIBILITY_MASK        0x0
#define NSMEQUITIES_ORDERS_INTER_MARKET_SWEEP_ELIGIBILITY_ENCODING    ENC_ASCII
#define NSMEQUITIES_ORDERS_INTER_MARKET_SWEEP_ELIGIBILITY_SIZE        1

static const value_string nsmequities_orders_inter_market_sweep_eligibility_vals[] = {
    { 'Y', "Eligible" },
    { 'N', "Not Eligible" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_inter_market_sweep_eligibility(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_inter_market_sweep_eligibility, tvb, offset, NSMEQUITIES_ORDERS_INTER_MARKET_SWEEP_ELIGIBILITY_SIZE, NSMEQUITIES_ORDERS_INTER_MARKET_SWEEP_ELIGIBILITY_ENCODING);

    return offset + NSMEQUITIES_ORDERS_INTER_MARKET_SWEEP_ELIGIBILITY_SIZE;
}

/* Intermarket Sweep Eligibility */
#define NSMEQUITIES_ORDERS_INTERMARKET_SWEEP_ELIGIBILITY_NAME     "Intermarket Sweep Eligibility"
#define NSMEQUITIES_ORDERS_INTERMARKET_SWEEP_ELIGIBILITY_FILTER   "nsmequities.orders.intermarketsweepeligibility"
#define NSMEQUITIES_ORDERS_INTERMARKET_SWEEP_ELIGIBILITY_TYPE     FT_CHAR
#define NSMEQUITIES_ORDERS_INTERMARKET_SWEEP_ELIGIBILITY_DISPLAY  BASE_HEX
#define NSMEQUITIES_ORDERS_INTERMARKET_SWEEP_ELIGIBILITY_MASK     0x0
#define NSMEQUITIES_ORDERS_INTERMARKET_SWEEP_ELIGIBILITY_ENCODING ENC_ASCII
#define NSMEQUITIES_ORDERS_INTERMARKET_SWEEP_ELIGIBILITY_SIZE     1

static const value_string nsmequities_orders_intermarket_sweep_eligibility_vals[] = {
    { 'Y', "Eligible" },
    { 'N', "Not Eligible" },
    { 'y', "Tradeat" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_intermarket_sweep_eligibility(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_intermarket_sweep_eligibility, tvb, offset, NSMEQUITIES_ORDERS_INTERMARKET_SWEEP_ELIGIBILITY_SIZE, NSMEQUITIES_ORDERS_INTERMARKET_SWEEP_ELIGIBILITY_ENCODING);

    return offset + NSMEQUITIES_ORDERS_INTERMARKET_SWEEP_ELIGIBILITY_SIZE;
}

/* Liquidity Flag */
#define NSMEQUITIES_ORDERS_LIQUIDITY_FLAG_NAME        "Liquidity Flag"
#define NSMEQUITIES_ORDERS_LIQUIDITY_FLAG_DESCRIPTION "Liquidity flag the order would have received."
#define NSMEQUITIES_ORDERS_LIQUIDITY_FLAG_FILTER      "nsmequities.orders.liquidityflag"
#define NSMEQUITIES_ORDERS_LIQUIDITY_FLAG_TYPE        FT_CHAR
#define NSMEQUITIES_ORDERS_LIQUIDITY_FLAG_DISPLAY     BASE_HEX
#define NSMEQUITIES_ORDERS_LIQUIDITY_FLAG_MASK        0x0
#define NSMEQUITIES_ORDERS_LIQUIDITY_FLAG_ENCODING    ENC_ASCII
#define NSMEQUITIES_ORDERS_LIQUIDITY_FLAG_SIZE        1

static const value_string nsmequities_orders_liquidity_flag_vals[] = {
    { 'A', "Added" },
    { 'C', "Closing" },
    { 'e', "Retail Designated" },
    { 'H', "Halt Ipo" },
    { 'i', "After Hours Closing" },
    { 'J', "Nondisplayed Adding Liquidity" },
    { 'j', "Rpi Order Provides Liquidity" },
    { 'k', "Added Liquidity Via A Midpoint Order" },
    { 'K', "Halt Cross" },
    { 'L', "Closing Cross" },
    { 'M', "Opening Cross" },
    { 'm', "Removed Liquidity At A Midpoint" },
    { 'N', "Passive Midpoint Execution" },
    { 'n', "Midpoint Extended Life Order Execution" },
    { 'O', "Opening" },
    { 'p', "Removed Price Improving Nondisplayed Liquidity" },
    { 'q', "Rmo Retail Order Removes Non Rpi Midpoint Liquidity" },
    { 'R', "Removed" },
    { 'r', "Retail Order Removes Rpi Liquidity" },
    { 't', "Retail Order Removes Price Improving Nondisplayed Liquidity Other Than Rpi Liquidity" },
    { 'u', "Added Nondisplayed Liquidity Via A Reserve Order" },
    { '0', "Supplemental" },
    { '7', "Displayed Liquidityadding Order Improves The Nbbo" },
    { '8', "Displayed Liquidityadding Order Sets The Qbbo While Joining The Nbbo" },
    { '1', "Rpi Order Provides Liquidity No Rpii" },
    { '2', "Added In The Premarket" },
    { '3', "Removed In The Premarket" },
    { '5', "Displayed Liquidityadding Order Improves The Nbbo In The Premarket" },
    { '9', "Nondisplayed Adding Liquidity In The Premarket" },
    { 'W', "Added Post Only" },
    { 'd', "Retail Designated Removed Liquidity" },
    { 'f', "Retail Designated Added Non Displayed Liquidity" },
    { '4', "Added Displayed In Group A" },
    { '6', "Removed In Group A" },
    { 'g', "Added Non Displayed Mid Point In Group A" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_liquidity_flag(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_liquidity_flag, tvb, offset, NSMEQUITIES_ORDERS_LIQUIDITY_FLAG_SIZE, NSMEQUITIES_ORDERS_LIQUIDITY_FLAG_ENCODING);

    return offset + NSMEQUITIES_ORDERS_LIQUIDITY_FLAG_SIZE;
}

/* Locate Broker */
#define NSMEQUITIES_ORDERS_LOCATE_BROKER_NAME        "Locate Broker"
#define NSMEQUITIES_ORDERS_LOCATE_BROKER_DESCRIPTION "Broker code from which the locate has been acquired for short sale orders"
#define NSMEQUITIES_ORDERS_LOCATE_BROKER_FILTER      "nsmequities.orders.locatebroker"
#define NSMEQUITIES_ORDERS_LOCATE_BROKER_TYPE        FT_STRING
#define NSMEQUITIES_ORDERS_LOCATE_BROKER_DISPLAY     BASE_NONE
#define NSMEQUITIES_ORDERS_LOCATE_BROKER_MASK        0x0
#define NSMEQUITIES_ORDERS_LOCATE_BROKER_ENCODING    ENC_ASCII
#define NSMEQUITIES_ORDERS_LOCATE_BROKER_SIZE        4

static unsigned
parse_nsmequities_orders_locate_broker(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_locate_broker, tvb, offset, NSMEQUITIES_ORDERS_LOCATE_BROKER_SIZE, NSMEQUITIES_ORDERS_LOCATE_BROKER_ENCODING);

    return offset + NSMEQUITIES_ORDERS_LOCATE_BROKER_SIZE;
}

/* Mass Cancel Request Optional Field values the dispatch switches on */
#define NSMEQUITIES_ORDERS_MASS_CANCEL_REQUEST_OPTIONAL_FIELD_SIDE       27
#define NSMEQUITIES_ORDERS_MASS_CANCEL_REQUEST_OPTIONAL_FIELD_GROUP_ID   24
#define NSMEQUITIES_ORDERS_MASS_CANCEL_REQUEST_OPTIONAL_FIELD_USERREFIDX 28

/* Mass Cancel Request Optional Field */
#define NSMEQUITIES_ORDERS_MASS_CANCEL_REQUEST_OPTIONAL_FIELD_NAME        "Mass Cancel Request Optional Field"
#define NSMEQUITIES_ORDERS_MASS_CANCEL_REQUEST_OPTIONAL_FIELD_DESCRIPTION "Appendage Id"
#define NSMEQUITIES_ORDERS_MASS_CANCEL_REQUEST_OPTIONAL_FIELD_FILTER      "nsmequities.orders.masscancelrequestoptionalfield"
#define NSMEQUITIES_ORDERS_MASS_CANCEL_REQUEST_OPTIONAL_FIELD_TYPE        FT_UINT8
#define NSMEQUITIES_ORDERS_MASS_CANCEL_REQUEST_OPTIONAL_FIELD_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_MASS_CANCEL_REQUEST_OPTIONAL_FIELD_MASK        0x0
#define NSMEQUITIES_ORDERS_MASS_CANCEL_REQUEST_OPTIONAL_FIELD_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_MASS_CANCEL_REQUEST_OPTIONAL_FIELD_SIZE        1

static const value_string nsmequities_orders_mass_cancel_request_optional_field_vals[] = {
    { NSMEQUITIES_ORDERS_MASS_CANCEL_REQUEST_OPTIONAL_FIELD_SIDE, "Side" },
    { NSMEQUITIES_ORDERS_MASS_CANCEL_REQUEST_OPTIONAL_FIELD_GROUP_ID, "Group ID" },
    { NSMEQUITIES_ORDERS_MASS_CANCEL_REQUEST_OPTIONAL_FIELD_USERREFIDX, "UserRefIdx" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_mass_cancel_request_optional_field(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_mass_cancel_request_optional_field, tvb, offset, NSMEQUITIES_ORDERS_MASS_CANCEL_REQUEST_OPTIONAL_FIELD_SIZE, NSMEQUITIES_ORDERS_MASS_CANCEL_REQUEST_OPTIONAL_FIELD_ENCODING);

    return offset + NSMEQUITIES_ORDERS_MASS_CANCEL_REQUEST_OPTIONAL_FIELD_SIZE;
}

/* Mass Cancel Response Optional Field values the dispatch switches on */
#define NSMEQUITIES_ORDERS_MASS_CANCEL_RESPONSE_OPTIONAL_FIELD_SIDE       27
#define NSMEQUITIES_ORDERS_MASS_CANCEL_RESPONSE_OPTIONAL_FIELD_GROUP_ID   24
#define NSMEQUITIES_ORDERS_MASS_CANCEL_RESPONSE_OPTIONAL_FIELD_USERREFIDX 28

/* Mass Cancel Response Optional Field */
#define NSMEQUITIES_ORDERS_MASS_CANCEL_RESPONSE_OPTIONAL_FIELD_NAME        "Mass Cancel Response Optional Field"
#define NSMEQUITIES_ORDERS_MASS_CANCEL_RESPONSE_OPTIONAL_FIELD_DESCRIPTION "Appendage Id"
#define NSMEQUITIES_ORDERS_MASS_CANCEL_RESPONSE_OPTIONAL_FIELD_FILTER      "nsmequities.orders.masscancelresponseoptionalfield"
#define NSMEQUITIES_ORDERS_MASS_CANCEL_RESPONSE_OPTIONAL_FIELD_TYPE        FT_UINT8
#define NSMEQUITIES_ORDERS_MASS_CANCEL_RESPONSE_OPTIONAL_FIELD_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_MASS_CANCEL_RESPONSE_OPTIONAL_FIELD_MASK        0x0
#define NSMEQUITIES_ORDERS_MASS_CANCEL_RESPONSE_OPTIONAL_FIELD_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_MASS_CANCEL_RESPONSE_OPTIONAL_FIELD_SIZE        1

static const value_string nsmequities_orders_mass_cancel_response_optional_field_vals[] = {
    { NSMEQUITIES_ORDERS_MASS_CANCEL_RESPONSE_OPTIONAL_FIELD_SIDE, "Side" },
    { NSMEQUITIES_ORDERS_MASS_CANCEL_RESPONSE_OPTIONAL_FIELD_GROUP_ID, "Group ID" },
    { NSMEQUITIES_ORDERS_MASS_CANCEL_RESPONSE_OPTIONAL_FIELD_USERREFIDX, "UserRefIdx" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_mass_cancel_response_optional_field(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_mass_cancel_response_optional_field, tvb, offset, NSMEQUITIES_ORDERS_MASS_CANCEL_RESPONSE_OPTIONAL_FIELD_SIZE, NSMEQUITIES_ORDERS_MASS_CANCEL_RESPONSE_OPTIONAL_FIELD_ENCODING);

    return offset + NSMEQUITIES_ORDERS_MASS_CANCEL_RESPONSE_OPTIONAL_FIELD_SIZE;
}

/* Match Number */
#define NSMEQUITIES_ORDERS_MATCH_NUMBER_NAME        "Match Number"
#define NSMEQUITIES_ORDERS_MATCH_NUMBER_DESCRIPTION "Assigned by the exchange to identify the trade. Both the buy and the sell executions participating in the trade will share the same match number."
#define NSMEQUITIES_ORDERS_MATCH_NUMBER_FILTER      "nsmequities.orders.matchnumber"
#define NSMEQUITIES_ORDERS_MATCH_NUMBER_TYPE        FT_UINT64
#define NSMEQUITIES_ORDERS_MATCH_NUMBER_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_MATCH_NUMBER_MASK        0x0
#define NSMEQUITIES_ORDERS_MATCH_NUMBER_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_MATCH_NUMBER_SIZE        8

static unsigned
parse_nsmequities_orders_match_number(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_match_number, tvb, offset, NSMEQUITIES_ORDERS_MATCH_NUMBER_SIZE, NSMEQUITIES_ORDERS_MATCH_NUMBER_ENCODING);

    return offset + NSMEQUITIES_ORDERS_MATCH_NUMBER_SIZE;
}

/* Max Floor */
#define NSMEQUITIES_ORDERS_MAX_FLOOR_NAME        "Max Floor"
#define NSMEQUITIES_ORDERS_MAX_FLOOR_DESCRIPTION "Represents the portion of your order that you wish to have displayed."
#define NSMEQUITIES_ORDERS_MAX_FLOOR_FILTER      "nsmequities.orders.maxfloor"
#define NSMEQUITIES_ORDERS_MAX_FLOOR_TYPE        FT_UINT32
#define NSMEQUITIES_ORDERS_MAX_FLOOR_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_MAX_FLOOR_MASK        0x0
#define NSMEQUITIES_ORDERS_MAX_FLOOR_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_MAX_FLOOR_SIZE        4

static unsigned
parse_nsmequities_orders_max_floor(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_max_floor, tvb, offset, NSMEQUITIES_ORDERS_MAX_FLOOR_SIZE, NSMEQUITIES_ORDERS_MAX_FLOOR_ENCODING);

    return offset + NSMEQUITIES_ORDERS_MAX_FLOOR_SIZE;
}

/* Min Qty */
#define NSMEQUITIES_ORDERS_MIN_QTY_NAME        "Min Qty"
#define NSMEQUITIES_ORDERS_MIN_QTY_DESCRIPTION "MinQty must be a round lot."
#define NSMEQUITIES_ORDERS_MIN_QTY_FILTER      "nsmequities.orders.minqty"
#define NSMEQUITIES_ORDERS_MIN_QTY_TYPE        FT_UINT32
#define NSMEQUITIES_ORDERS_MIN_QTY_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_MIN_QTY_MASK        0x0
#define NSMEQUITIES_ORDERS_MIN_QTY_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_MIN_QTY_SIZE        4

static unsigned
parse_nsmequities_orders_min_qty(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_min_qty, tvb, offset, NSMEQUITIES_ORDERS_MIN_QTY_SIZE, NSMEQUITIES_ORDERS_MIN_QTY_ENCODING);

    return offset + NSMEQUITIES_ORDERS_MIN_QTY_SIZE;
}

/* Minimum Quantity */
#define NSMEQUITIES_ORDERS_MINIMUM_QUANTITY_NAME        "Minimum Quantity"
#define NSMEQUITIES_ORDERS_MINIMUM_QUANTITY_DESCRIPTION "Specifies the minimum acceptable quantity to execute"
#define NSMEQUITIES_ORDERS_MINIMUM_QUANTITY_FILTER      "nsmequities.orders.minimumquantity"
#define NSMEQUITIES_ORDERS_MINIMUM_QUANTITY_TYPE        FT_UINT32
#define NSMEQUITIES_ORDERS_MINIMUM_QUANTITY_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_MINIMUM_QUANTITY_MASK        0x0
#define NSMEQUITIES_ORDERS_MINIMUM_QUANTITY_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_MINIMUM_QUANTITY_SIZE        4

static unsigned
parse_nsmequities_orders_minimum_quantity(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_minimum_quantity, tvb, offset, NSMEQUITIES_ORDERS_MINIMUM_QUANTITY_SIZE, NSMEQUITIES_ORDERS_MINIMUM_QUANTITY_ENCODING);

    return offset + NSMEQUITIES_ORDERS_MINIMUM_QUANTITY_SIZE;
}

/* Modify Order Optional Field values the dispatch switches on */
#define NSMEQUITIES_ORDERS_MODIFY_ORDER_OPTIONAL_FIELD_USERREFIDX     28
#define NSMEQUITIES_ORDERS_MODIFY_ORDER_OPTIONAL_FIELD_SHARES_LOCATED 25
#define NSMEQUITIES_ORDERS_MODIFY_ORDER_OPTIONAL_FIELD_LOCATE_BROKER  26

/* Modify Order Optional Field */
#define NSMEQUITIES_ORDERS_MODIFY_ORDER_OPTIONAL_FIELD_NAME        "Modify Order Optional Field"
#define NSMEQUITIES_ORDERS_MODIFY_ORDER_OPTIONAL_FIELD_DESCRIPTION "Appendage Id"
#define NSMEQUITIES_ORDERS_MODIFY_ORDER_OPTIONAL_FIELD_FILTER      "nsmequities.orders.modifyorderoptionalfield"
#define NSMEQUITIES_ORDERS_MODIFY_ORDER_OPTIONAL_FIELD_TYPE        FT_UINT8
#define NSMEQUITIES_ORDERS_MODIFY_ORDER_OPTIONAL_FIELD_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_MODIFY_ORDER_OPTIONAL_FIELD_MASK        0x0
#define NSMEQUITIES_ORDERS_MODIFY_ORDER_OPTIONAL_FIELD_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_MODIFY_ORDER_OPTIONAL_FIELD_SIZE        1

static const value_string nsmequities_orders_modify_order_optional_field_vals[] = {
    { NSMEQUITIES_ORDERS_MODIFY_ORDER_OPTIONAL_FIELD_USERREFIDX, "UserRefIdx" },
    { NSMEQUITIES_ORDERS_MODIFY_ORDER_OPTIONAL_FIELD_SHARES_LOCATED, "Shares Located" },
    { NSMEQUITIES_ORDERS_MODIFY_ORDER_OPTIONAL_FIELD_LOCATE_BROKER, "Locate Broker" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_modify_order_optional_field(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_modify_order_optional_field, tvb, offset, NSMEQUITIES_ORDERS_MODIFY_ORDER_OPTIONAL_FIELD_SIZE, NSMEQUITIES_ORDERS_MODIFY_ORDER_OPTIONAL_FIELD_ENCODING);

    return offset + NSMEQUITIES_ORDERS_MODIFY_ORDER_OPTIONAL_FIELD_SIZE;
}

/* Next User Ref Num */
#define NSMEQUITIES_ORDERS_NEXT_USER_REF_NUM_NAME        "Next User Ref Num"
#define NSMEQUITIES_ORDERS_NEXT_USER_REF_NUM_DESCRIPTION "The next available UserRefNum"
#define NSMEQUITIES_ORDERS_NEXT_USER_REF_NUM_FILTER      "nsmequities.orders.nextuserrefnum"
#define NSMEQUITIES_ORDERS_NEXT_USER_REF_NUM_TYPE        FT_UINT32
#define NSMEQUITIES_ORDERS_NEXT_USER_REF_NUM_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_NEXT_USER_REF_NUM_MASK        0x0
#define NSMEQUITIES_ORDERS_NEXT_USER_REF_NUM_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_NEXT_USER_REF_NUM_SIZE        4

static unsigned
parse_nsmequities_orders_next_user_ref_num(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_next_user_ref_num, tvb, offset, NSMEQUITIES_ORDERS_NEXT_USER_REF_NUM_SIZE, NSMEQUITIES_ORDERS_NEXT_USER_REF_NUM_ENCODING);

    return offset + NSMEQUITIES_ORDERS_NEXT_USER_REF_NUM_SIZE;
}

/* Optional Field Length */
#define NSMEQUITIES_ORDERS_OPTIONAL_FIELD_LENGTH_NAME        "Optional Field Length"
#define NSMEQUITIES_ORDERS_OPTIONAL_FIELD_LENGTH_DESCRIPTION "Appendage Length Type"
#define NSMEQUITIES_ORDERS_OPTIONAL_FIELD_LENGTH_FILTER      "nsmequities.orders.optionalfieldlength"
#define NSMEQUITIES_ORDERS_OPTIONAL_FIELD_LENGTH_TYPE        FT_UINT8
#define NSMEQUITIES_ORDERS_OPTIONAL_FIELD_LENGTH_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_OPTIONAL_FIELD_LENGTH_MASK        0x0
#define NSMEQUITIES_ORDERS_OPTIONAL_FIELD_LENGTH_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_OPTIONAL_FIELD_LENGTH_SIZE        1

static unsigned
parse_nsmequities_orders_optional_field_length(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_optional_field_length, tvb, offset, NSMEQUITIES_ORDERS_OPTIONAL_FIELD_LENGTH_SIZE, NSMEQUITIES_ORDERS_OPTIONAL_FIELD_LENGTH_ENCODING);

    return offset + NSMEQUITIES_ORDERS_OPTIONAL_FIELD_LENGTH_SIZE;
}

/* Order Accepted Optional Field values the dispatch switches on */
#define NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_FIRM                 2
#define NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_MINQTY               3
#define NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_CUSTOMERTYPE         4
#define NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_MAXFLOOR             5
#define NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_PRICETYPE            6
#define NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_PEGOFFSET            7
#define NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_DISCRETIONPRICE      9
#define NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_DISCRETIONPRICETYPE  10
#define NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_DISCRETIONPEGOFFSET  11
#define NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_POSTONLY             12
#define NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_RANDOMRESERVES       13
#define NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_ROUTE                14
#define NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_EXPIRETIME           15
#define NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_TRADENOW             16
#define NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_HANDLEINST           17
#define NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_BBO_WEIGHT_INDICATOR 18
#define NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_GROUP_ID             24
#define NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_SHARES_LOCATED       25
#define NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_USERREFIDX           28
#define NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_AIQ_STRATEGY         29
#define NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_AIQ_GROUP_ID         30

/* Order Accepted Optional Field */
#define NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_NAME        "Order Accepted Optional Field"
#define NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_DESCRIPTION "Appendage Id"
#define NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_FILTER      "nsmequities.orders.orderacceptedoptionalfield"
#define NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_TYPE        FT_UINT8
#define NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_MASK        0x0
#define NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_SIZE        1

static const value_string nsmequities_orders_order_accepted_optional_field_vals[] = {
    { NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_FIRM, "Firm" },
    { NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_MINQTY, "MinQty" },
    { NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_CUSTOMERTYPE, "CustomerType" },
    { NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_MAXFLOOR, "MaxFloor" },
    { NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_PRICETYPE, "PriceType" },
    { NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_PEGOFFSET, "PegOffset" },
    { NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_DISCRETIONPRICE, "DiscretionPrice" },
    { NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_DISCRETIONPRICETYPE, "DiscretionPriceType" },
    { NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_DISCRETIONPEGOFFSET, "DiscretionPegOffset" },
    { NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_POSTONLY, "PostOnly" },
    { NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_RANDOMRESERVES, "RandomReserves" },
    { NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_ROUTE, "Route" },
    { NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_EXPIRETIME, "ExpireTime" },
    { NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_TRADENOW, "TradeNow" },
    { NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_HANDLEINST, "HandleInst" },
    { NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_BBO_WEIGHT_INDICATOR, "BBO Weight Indicator" },
    { NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_GROUP_ID, "Group ID" },
    { NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_SHARES_LOCATED, "Shares Located" },
    { NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_USERREFIDX, "UserRefIdx" },
    { NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_AIQ_STRATEGY, "AIQ Strategy" },
    { NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_AIQ_GROUP_ID, "AIQ Group ID" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_order_accepted_optional_field(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_order_accepted_optional_field, tvb, offset, NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_SIZE, NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_ENCODING);

    return offset + NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_SIZE;
}

/* Order Cancel Reason */
#define NSMEQUITIES_ORDERS_ORDER_CANCEL_REASON_NAME        "Order Cancel Reason"
#define NSMEQUITIES_ORDERS_ORDER_CANCEL_REASON_DESCRIPTION "Reason the order was reduced or canceled. For an AIQ Cancel message, this value will always be “Q”."
#define NSMEQUITIES_ORDERS_ORDER_CANCEL_REASON_FILTER      "nsmequities.orders.ordercancelreason"
#define NSMEQUITIES_ORDERS_ORDER_CANCEL_REASON_TYPE        FT_CHAR
#define NSMEQUITIES_ORDERS_ORDER_CANCEL_REASON_DISPLAY     BASE_HEX
#define NSMEQUITIES_ORDERS_ORDER_CANCEL_REASON_MASK        0x0
#define NSMEQUITIES_ORDERS_ORDER_CANCEL_REASON_ENCODING    ENC_ASCII
#define NSMEQUITIES_ORDERS_ORDER_CANCEL_REASON_SIZE        1

static unsigned
parse_nsmequities_orders_order_cancel_reason(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_order_cancel_reason, tvb, offset, NSMEQUITIES_ORDERS_ORDER_CANCEL_REASON_SIZE, NSMEQUITIES_ORDERS_ORDER_CANCEL_REASON_ENCODING);

    return offset + NSMEQUITIES_ORDERS_ORDER_CANCEL_REASON_SIZE;
}

/* Order Executed Optional Field values the dispatch switches on */
#define NSMEQUITIES_ORDERS_ORDER_EXECUTED_OPTIONAL_FIELD_USERREFIDX 28

/* Order Executed Optional Field */
#define NSMEQUITIES_ORDERS_ORDER_EXECUTED_OPTIONAL_FIELD_NAME        "Order Executed Optional Field"
#define NSMEQUITIES_ORDERS_ORDER_EXECUTED_OPTIONAL_FIELD_DESCRIPTION "Appendage Id"
#define NSMEQUITIES_ORDERS_ORDER_EXECUTED_OPTIONAL_FIELD_FILTER      "nsmequities.orders.orderexecutedoptionalfield"
#define NSMEQUITIES_ORDERS_ORDER_EXECUTED_OPTIONAL_FIELD_TYPE        FT_UINT8
#define NSMEQUITIES_ORDERS_ORDER_EXECUTED_OPTIONAL_FIELD_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_ORDER_EXECUTED_OPTIONAL_FIELD_MASK        0x0
#define NSMEQUITIES_ORDERS_ORDER_EXECUTED_OPTIONAL_FIELD_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_ORDER_EXECUTED_OPTIONAL_FIELD_SIZE        1

static const value_string nsmequities_orders_order_executed_optional_field_vals[] = {
    { NSMEQUITIES_ORDERS_ORDER_EXECUTED_OPTIONAL_FIELD_USERREFIDX, "UserRefIdx" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_order_executed_optional_field(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_order_executed_optional_field, tvb, offset, NSMEQUITIES_ORDERS_ORDER_EXECUTED_OPTIONAL_FIELD_SIZE, NSMEQUITIES_ORDERS_ORDER_EXECUTED_OPTIONAL_FIELD_ENCODING);

    return offset + NSMEQUITIES_ORDERS_ORDER_EXECUTED_OPTIONAL_FIELD_SIZE;
}

/* Order Modified Optional Field values the dispatch switches on */
#define NSMEQUITIES_ORDERS_ORDER_MODIFIED_OPTIONAL_FIELD_USERREFIDX     28
#define NSMEQUITIES_ORDERS_ORDER_MODIFIED_OPTIONAL_FIELD_SHARES_LOCATED 25
#define NSMEQUITIES_ORDERS_ORDER_MODIFIED_OPTIONAL_FIELD_LOCATE_BROKER  26

/* Order Modified Optional Field */
#define NSMEQUITIES_ORDERS_ORDER_MODIFIED_OPTIONAL_FIELD_NAME        "Order Modified Optional Field"
#define NSMEQUITIES_ORDERS_ORDER_MODIFIED_OPTIONAL_FIELD_DESCRIPTION "Appendage Id"
#define NSMEQUITIES_ORDERS_ORDER_MODIFIED_OPTIONAL_FIELD_FILTER      "nsmequities.orders.ordermodifiedoptionalfield"
#define NSMEQUITIES_ORDERS_ORDER_MODIFIED_OPTIONAL_FIELD_TYPE        FT_UINT8
#define NSMEQUITIES_ORDERS_ORDER_MODIFIED_OPTIONAL_FIELD_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_ORDER_MODIFIED_OPTIONAL_FIELD_MASK        0x0
#define NSMEQUITIES_ORDERS_ORDER_MODIFIED_OPTIONAL_FIELD_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_ORDER_MODIFIED_OPTIONAL_FIELD_SIZE        1

static const value_string nsmequities_orders_order_modified_optional_field_vals[] = {
    { NSMEQUITIES_ORDERS_ORDER_MODIFIED_OPTIONAL_FIELD_USERREFIDX, "UserRefIdx" },
    { NSMEQUITIES_ORDERS_ORDER_MODIFIED_OPTIONAL_FIELD_SHARES_LOCATED, "Shares Located" },
    { NSMEQUITIES_ORDERS_ORDER_MODIFIED_OPTIONAL_FIELD_LOCATE_BROKER, "Locate Broker" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_order_modified_optional_field(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_order_modified_optional_field, tvb, offset, NSMEQUITIES_ORDERS_ORDER_MODIFIED_OPTIONAL_FIELD_SIZE, NSMEQUITIES_ORDERS_ORDER_MODIFIED_OPTIONAL_FIELD_ENCODING);

    return offset + NSMEQUITIES_ORDERS_ORDER_MODIFIED_OPTIONAL_FIELD_SIZE;
}

/* Order Priority Update Optional Field values the dispatch switches on */
#define NSMEQUITIES_ORDERS_ORDER_PRIORITY_UPDATE_OPTIONAL_FIELD_USERREFIDX 28

/* Order Priority Update Optional Field */
#define NSMEQUITIES_ORDERS_ORDER_PRIORITY_UPDATE_OPTIONAL_FIELD_NAME        "Order Priority Update Optional Field"
#define NSMEQUITIES_ORDERS_ORDER_PRIORITY_UPDATE_OPTIONAL_FIELD_DESCRIPTION "Appendage Id"
#define NSMEQUITIES_ORDERS_ORDER_PRIORITY_UPDATE_OPTIONAL_FIELD_FILTER      "nsmequities.orders.orderpriorityupdateoptionalfield"
#define NSMEQUITIES_ORDERS_ORDER_PRIORITY_UPDATE_OPTIONAL_FIELD_TYPE        FT_UINT8
#define NSMEQUITIES_ORDERS_ORDER_PRIORITY_UPDATE_OPTIONAL_FIELD_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_ORDER_PRIORITY_UPDATE_OPTIONAL_FIELD_MASK        0x0
#define NSMEQUITIES_ORDERS_ORDER_PRIORITY_UPDATE_OPTIONAL_FIELD_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_ORDER_PRIORITY_UPDATE_OPTIONAL_FIELD_SIZE        1

static const value_string nsmequities_orders_order_priority_update_optional_field_vals[] = {
    { NSMEQUITIES_ORDERS_ORDER_PRIORITY_UPDATE_OPTIONAL_FIELD_USERREFIDX, "UserRefIdx" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_order_priority_update_optional_field(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_order_priority_update_optional_field, tvb, offset, NSMEQUITIES_ORDERS_ORDER_PRIORITY_UPDATE_OPTIONAL_FIELD_SIZE, NSMEQUITIES_ORDERS_ORDER_PRIORITY_UPDATE_OPTIONAL_FIELD_ENCODING);

    return offset + NSMEQUITIES_ORDERS_ORDER_PRIORITY_UPDATE_OPTIONAL_FIELD_SIZE;
}

/* Order Reference Number */
#define NSMEQUITIES_ORDERS_ORDER_REFERENCE_NUMBER_NAME        "Order Reference Number"
#define NSMEQUITIES_ORDERS_ORDER_REFERENCE_NUMBER_DESCRIPTION "The day-unique Order Reference Number assigned by NASDAQ to this order"
#define NSMEQUITIES_ORDERS_ORDER_REFERENCE_NUMBER_FILTER      "nsmequities.orders.orderreferencenumber"
#define NSMEQUITIES_ORDERS_ORDER_REFERENCE_NUMBER_TYPE        FT_UINT64
#define NSMEQUITIES_ORDERS_ORDER_REFERENCE_NUMBER_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_ORDER_REFERENCE_NUMBER_MASK        0x0
#define NSMEQUITIES_ORDERS_ORDER_REFERENCE_NUMBER_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_ORDER_REFERENCE_NUMBER_SIZE        8

static unsigned
parse_nsmequities_orders_order_reference_number(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_order_reference_number, tvb, offset, NSMEQUITIES_ORDERS_ORDER_REFERENCE_NUMBER_SIZE, NSMEQUITIES_ORDERS_ORDER_REFERENCE_NUMBER_ENCODING);

    return offset + NSMEQUITIES_ORDERS_ORDER_REFERENCE_NUMBER_SIZE;
}

/* Order Restated Optional Field values the dispatch switches on */
#define NSMEQUITIES_ORDERS_ORDER_RESTATED_OPTIONAL_FIELD_DISPLAY_QUANTITY   22
#define NSMEQUITIES_ORDERS_ORDER_RESTATED_OPTIONAL_FIELD_DISPLAY_PRICE      23
#define NSMEQUITIES_ORDERS_ORDER_RESTATED_OPTIONAL_FIELD_SECONDARYORDREFNUM 1
#define NSMEQUITIES_ORDERS_ORDER_RESTATED_OPTIONAL_FIELD_USERREFIDX         28

/* Order Restated Optional Field */
#define NSMEQUITIES_ORDERS_ORDER_RESTATED_OPTIONAL_FIELD_NAME        "Order Restated Optional Field"
#define NSMEQUITIES_ORDERS_ORDER_RESTATED_OPTIONAL_FIELD_DESCRIPTION "Appendage Id"
#define NSMEQUITIES_ORDERS_ORDER_RESTATED_OPTIONAL_FIELD_FILTER      "nsmequities.orders.orderrestatedoptionalfield"
#define NSMEQUITIES_ORDERS_ORDER_RESTATED_OPTIONAL_FIELD_TYPE        FT_UINT8
#define NSMEQUITIES_ORDERS_ORDER_RESTATED_OPTIONAL_FIELD_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_ORDER_RESTATED_OPTIONAL_FIELD_MASK        0x0
#define NSMEQUITIES_ORDERS_ORDER_RESTATED_OPTIONAL_FIELD_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_ORDER_RESTATED_OPTIONAL_FIELD_SIZE        1

static const value_string nsmequities_orders_order_restated_optional_field_vals[] = {
    { NSMEQUITIES_ORDERS_ORDER_RESTATED_OPTIONAL_FIELD_DISPLAY_QUANTITY, "Display Quantity" },
    { NSMEQUITIES_ORDERS_ORDER_RESTATED_OPTIONAL_FIELD_DISPLAY_PRICE, "Display Price" },
    { NSMEQUITIES_ORDERS_ORDER_RESTATED_OPTIONAL_FIELD_SECONDARYORDREFNUM, "SecondaryOrdRefNum" },
    { NSMEQUITIES_ORDERS_ORDER_RESTATED_OPTIONAL_FIELD_USERREFIDX, "UserRefIdx" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_order_restated_optional_field(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_order_restated_optional_field, tvb, offset, NSMEQUITIES_ORDERS_ORDER_RESTATED_OPTIONAL_FIELD_SIZE, NSMEQUITIES_ORDERS_ORDER_RESTATED_OPTIONAL_FIELD_ENCODING);

    return offset + NSMEQUITIES_ORDERS_ORDER_RESTATED_OPTIONAL_FIELD_SIZE;
}

/* Order Restated Reason */
#define NSMEQUITIES_ORDERS_ORDER_RESTATED_REASON_NAME        "Order Restated Reason"
#define NSMEQUITIES_ORDERS_ORDER_RESTATED_REASON_DESCRIPTION "The reason for this order being restated"
#define NSMEQUITIES_ORDERS_ORDER_RESTATED_REASON_FILTER      "nsmequities.orders.orderrestatedreason"
#define NSMEQUITIES_ORDERS_ORDER_RESTATED_REASON_TYPE        FT_CHAR
#define NSMEQUITIES_ORDERS_ORDER_RESTATED_REASON_DISPLAY     BASE_HEX
#define NSMEQUITIES_ORDERS_ORDER_RESTATED_REASON_MASK        0x0
#define NSMEQUITIES_ORDERS_ORDER_RESTATED_REASON_ENCODING    ENC_ASCII
#define NSMEQUITIES_ORDERS_ORDER_RESTATED_REASON_SIZE        1

static const value_string nsmequities_orders_order_restated_reason_vals[] = {
    { 'R', "Refresh Of Display" },
    { 'P', "Update Of Displayed Price" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_order_restated_reason(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_order_restated_reason, tvb, offset, NSMEQUITIES_ORDERS_ORDER_RESTATED_REASON_SIZE, NSMEQUITIES_ORDERS_ORDER_RESTATED_REASON_ENCODING);

    return offset + NSMEQUITIES_ORDERS_ORDER_RESTATED_REASON_SIZE;
}

/* Order State */
#define NSMEQUITIES_ORDERS_ORDER_STATE_NAME     "Order State"
#define NSMEQUITIES_ORDERS_ORDER_STATE_FILTER   "nsmequities.orders.orderstate"
#define NSMEQUITIES_ORDERS_ORDER_STATE_TYPE     FT_CHAR
#define NSMEQUITIES_ORDERS_ORDER_STATE_DISPLAY  BASE_HEX
#define NSMEQUITIES_ORDERS_ORDER_STATE_MASK     0x0
#define NSMEQUITIES_ORDERS_ORDER_STATE_ENCODING ENC_ASCII
#define NSMEQUITIES_ORDERS_ORDER_STATE_SIZE     1

static const value_string nsmequities_orders_order_state_vals[] = {
    { 'L', "Order Live" },
    { 'D', "Order Dead" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_order_state(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_order_state, tvb, offset, NSMEQUITIES_ORDERS_ORDER_STATE_SIZE, NSMEQUITIES_ORDERS_ORDER_STATE_ENCODING);

    return offset + NSMEQUITIES_ORDERS_ORDER_STATE_SIZE;
}

/* Order Token */
#define NSMEQUITIES_ORDERS_ORDER_TOKEN_NAME        "Order Token"
#define NSMEQUITIES_ORDERS_ORDER_TOKEN_DESCRIPTION "As described above in Data Types. You can put any information you like. Token must be day-unique for each OUCH account."
#define NSMEQUITIES_ORDERS_ORDER_TOKEN_FILTER      "nsmequities.orders.ordertoken"
#define NSMEQUITIES_ORDERS_ORDER_TOKEN_TYPE        FT_STRING
#define NSMEQUITIES_ORDERS_ORDER_TOKEN_DISPLAY     BASE_NONE
#define NSMEQUITIES_ORDERS_ORDER_TOKEN_MASK        0x0
#define NSMEQUITIES_ORDERS_ORDER_TOKEN_ENCODING    ENC_ASCII
#define NSMEQUITIES_ORDERS_ORDER_TOKEN_SIZE        14

static unsigned
parse_nsmequities_orders_order_token(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_order_token, tvb, offset, NSMEQUITIES_ORDERS_ORDER_TOKEN_SIZE, NSMEQUITIES_ORDERS_ORDER_TOKEN_ENCODING);

    return offset + NSMEQUITIES_ORDERS_ORDER_TOKEN_SIZE;
}

/* Orig User Ref Num */
#define NSMEQUITIES_ORDERS_ORIG_USER_REF_NUM_NAME        "Orig User Ref Num"
#define NSMEQUITIES_ORDERS_ORIG_USER_REF_NUM_DESCRIPTION "This must be filled out with the Order UserRefNum sent on the Enter Order Message or last Replace Order Message."
#define NSMEQUITIES_ORDERS_ORIG_USER_REF_NUM_FILTER      "nsmequities.orders.origuserrefnum"
#define NSMEQUITIES_ORDERS_ORIG_USER_REF_NUM_TYPE        FT_UINT32
#define NSMEQUITIES_ORDERS_ORIG_USER_REF_NUM_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_ORIG_USER_REF_NUM_MASK        0x0
#define NSMEQUITIES_ORDERS_ORIG_USER_REF_NUM_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_ORIG_USER_REF_NUM_SIZE        4

static unsigned
parse_nsmequities_orders_orig_user_ref_num(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_orig_user_ref_num, tvb, offset, NSMEQUITIES_ORDERS_ORIG_USER_REF_NUM_SIZE, NSMEQUITIES_ORDERS_ORIG_USER_REF_NUM_ENCODING);

    return offset + NSMEQUITIES_ORDERS_ORIG_USER_REF_NUM_SIZE;
}

/* Packet Length */
#define NSMEQUITIES_ORDERS_PACKET_LENGTH_NAME        "Packet Length"
#define NSMEQUITIES_ORDERS_PACKET_LENGTH_DESCRIPTION "Length of data message not including this field"
#define NSMEQUITIES_ORDERS_PACKET_LENGTH_FILTER      "nsmequities.orders.packetlength"
#define NSMEQUITIES_ORDERS_PACKET_LENGTH_TYPE        FT_UINT16
#define NSMEQUITIES_ORDERS_PACKET_LENGTH_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_PACKET_LENGTH_MASK        0x0
#define NSMEQUITIES_ORDERS_PACKET_LENGTH_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_PACKET_LENGTH_SIZE        2

static unsigned
parse_nsmequities_orders_packet_length(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_packet_length, tvb, offset, NSMEQUITIES_ORDERS_PACKET_LENGTH_SIZE, NSMEQUITIES_ORDERS_PACKET_LENGTH_ENCODING);

    return offset + NSMEQUITIES_ORDERS_PACKET_LENGTH_SIZE;
}

/* Password */
#define NSMEQUITIES_ORDERS_PASSWORD_NAME        "Password"
#define NSMEQUITIES_ORDERS_PASSWORD_DESCRIPTION "Login password"
#define NSMEQUITIES_ORDERS_PASSWORD_FILTER      "nsmequities.orders.password"
#define NSMEQUITIES_ORDERS_PASSWORD_TYPE        FT_STRING
#define NSMEQUITIES_ORDERS_PASSWORD_DISPLAY     BASE_NONE
#define NSMEQUITIES_ORDERS_PASSWORD_MASK        0x0
#define NSMEQUITIES_ORDERS_PASSWORD_ENCODING    ENC_ASCII
#define NSMEQUITIES_ORDERS_PASSWORD_SIZE        10

static unsigned
parse_nsmequities_orders_password(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_password, tvb, offset, NSMEQUITIES_ORDERS_PASSWORD_SIZE, NSMEQUITIES_ORDERS_PASSWORD_ENCODING);

    return offset + NSMEQUITIES_ORDERS_PASSWORD_SIZE;
}

/* Peg Offset */
#define NSMEQUITIES_ORDERS_PEG_OFFSET_NAME        "Peg Offset"
#define NSMEQUITIES_ORDERS_PEG_OFFSET_DESCRIPTION "Offset amount for the pegged value."
#define NSMEQUITIES_ORDERS_PEG_OFFSET_FILTER      "nsmequities.orders.pegoffset"
#define NSMEQUITIES_ORDERS_PEG_OFFSET_TYPE        FT_INT32
#define NSMEQUITIES_ORDERS_PEG_OFFSET_DISPLAY     BASE_CUSTOM
#define NSMEQUITIES_ORDERS_PEG_OFFSET_MASK        0x0
#define NSMEQUITIES_ORDERS_PEG_OFFSET_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_PEG_OFFSET_SIZE        4

static unsigned
parse_nsmequities_orders_peg_offset(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_peg_offset, tvb, offset, NSMEQUITIES_ORDERS_PEG_OFFSET_SIZE, NSMEQUITIES_ORDERS_PEG_OFFSET_ENCODING);

    return offset + NSMEQUITIES_ORDERS_PEG_OFFSET_SIZE;
}

/* Post Only */
#define NSMEQUITIES_ORDERS_POST_ONLY_NAME        "Post Only"
#define NSMEQUITIES_ORDERS_POST_ONLY_DESCRIPTION "PostOnly"
#define NSMEQUITIES_ORDERS_POST_ONLY_FILTER      "nsmequities.orders.postonly"
#define NSMEQUITIES_ORDERS_POST_ONLY_TYPE        FT_CHAR
#define NSMEQUITIES_ORDERS_POST_ONLY_DISPLAY     BASE_HEX
#define NSMEQUITIES_ORDERS_POST_ONLY_MASK        0x0
#define NSMEQUITIES_ORDERS_POST_ONLY_ENCODING    ENC_ASCII
#define NSMEQUITIES_ORDERS_POST_ONLY_SIZE        1

static const value_string nsmequities_orders_post_only_vals[] = {
    { 'P', "Post Only" },
    { 'N', "No" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_post_only(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_post_only, tvb, offset, NSMEQUITIES_ORDERS_POST_ONLY_SIZE, NSMEQUITIES_ORDERS_POST_ONLY_ENCODING);

    return offset + NSMEQUITIES_ORDERS_POST_ONLY_SIZE;
}

/* Previous Order Token */
#define NSMEQUITIES_ORDERS_PREVIOUS_ORDER_TOKEN_NAME        "Previous Order Token"
#define NSMEQUITIES_ORDERS_PREVIOUS_ORDER_TOKEN_DESCRIPTION "The Order Token of the order that was replaced"
#define NSMEQUITIES_ORDERS_PREVIOUS_ORDER_TOKEN_FILTER      "nsmequities.orders.previousordertoken"
#define NSMEQUITIES_ORDERS_PREVIOUS_ORDER_TOKEN_TYPE        FT_STRING
#define NSMEQUITIES_ORDERS_PREVIOUS_ORDER_TOKEN_DISPLAY     BASE_NONE
#define NSMEQUITIES_ORDERS_PREVIOUS_ORDER_TOKEN_MASK        0x0
#define NSMEQUITIES_ORDERS_PREVIOUS_ORDER_TOKEN_ENCODING    ENC_ASCII
#define NSMEQUITIES_ORDERS_PREVIOUS_ORDER_TOKEN_SIZE        14

static unsigned
parse_nsmequities_orders_previous_order_token(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_previous_order_token, tvb, offset, NSMEQUITIES_ORDERS_PREVIOUS_ORDER_TOKEN_SIZE, NSMEQUITIES_ORDERS_PREVIOUS_ORDER_TOKEN_ENCODING);

    return offset + NSMEQUITIES_ORDERS_PREVIOUS_ORDER_TOKEN_SIZE;
}

/* Price */
#define NSMEQUITIES_ORDERS_PRICE_NAME        "Price"
#define NSMEQUITIES_ORDERS_PRICE_DESCRIPTION "The price of the order."
#define NSMEQUITIES_ORDERS_PRICE_FILTER      "nsmequities.orders.price"
#define NSMEQUITIES_ORDERS_PRICE_TYPE        FT_UINT64
#define NSMEQUITIES_ORDERS_PRICE_DISPLAY     BASE_CUSTOM
#define NSMEQUITIES_ORDERS_PRICE_MASK        0x0
#define NSMEQUITIES_ORDERS_PRICE_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_PRICE_SIZE        8

static unsigned
parse_nsmequities_orders_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_price, tvb, offset, NSMEQUITIES_ORDERS_PRICE_SIZE, NSMEQUITIES_ORDERS_PRICE_ENCODING);

    return offset + NSMEQUITIES_ORDERS_PRICE_SIZE;
}

/* Price V422018 */
#define NSMEQUITIES_ORDERS_PRICE_V422018_NAME        "Price"
#define NSMEQUITIES_ORDERS_PRICE_V422018_DESCRIPTION "The price of the order. Please refer to the section in Data Types for more clarification."
#define NSMEQUITIES_ORDERS_PRICE_V422018_FILTER      "nsmequities.orders.price"
#define NSMEQUITIES_ORDERS_PRICE_V422018_TYPE        FT_UINT32
#define NSMEQUITIES_ORDERS_PRICE_V422018_DISPLAY     BASE_CUSTOM
#define NSMEQUITIES_ORDERS_PRICE_V422018_MASK        0x0
#define NSMEQUITIES_ORDERS_PRICE_V422018_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_PRICE_V422018_SIZE        4

static unsigned
parse_nsmequities_orders_price_v422018(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_price_v422018, tvb, offset, NSMEQUITIES_ORDERS_PRICE_V422018_SIZE, NSMEQUITIES_ORDERS_PRICE_V422018_ENCODING);

    return offset + NSMEQUITIES_ORDERS_PRICE_V422018_SIZE;
}

/* Price Type */
#define NSMEQUITIES_ORDERS_PRICE_TYPE_NAME        "Price Type"
#define NSMEQUITIES_ORDERS_PRICE_TYPE_DESCRIPTION "PriceType"
#define NSMEQUITIES_ORDERS_PRICE_TYPE_FILTER      "nsmequities.orders.pricetype"
#define NSMEQUITIES_ORDERS_PRICE_TYPE_TYPE        FT_CHAR
#define NSMEQUITIES_ORDERS_PRICE_TYPE_DISPLAY     BASE_HEX
#define NSMEQUITIES_ORDERS_PRICE_TYPE_MASK        0x0
#define NSMEQUITIES_ORDERS_PRICE_TYPE_ENCODING    ENC_ASCII
#define NSMEQUITIES_ORDERS_PRICE_TYPE_SIZE        1

static const value_string nsmequities_orders_price_type_vals[] = {
    { 'L', "Limit" },
    { 'P', "Market Peg" },
    { 'M', "Midpoint Peg" },
    { 'R', "Primary Peg" },
    { 'Q', "Market Maker Peg" },
    { 'm', "Midpoint" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_price_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_price_type, tvb, offset, NSMEQUITIES_ORDERS_PRICE_TYPE_SIZE, NSMEQUITIES_ORDERS_PRICE_TYPE_ENCODING);

    return offset + NSMEQUITIES_ORDERS_PRICE_TYPE_SIZE;
}

/* Quantity */
#define NSMEQUITIES_ORDERS_QUANTITY_NAME        "Quantity"
#define NSMEQUITIES_ORDERS_QUANTITY_DESCRIPTION "Total number of shares. Must be greater than zero and less than 1,000,000."
#define NSMEQUITIES_ORDERS_QUANTITY_FILTER      "nsmequities.orders.quantity"
#define NSMEQUITIES_ORDERS_QUANTITY_TYPE        FT_UINT32
#define NSMEQUITIES_ORDERS_QUANTITY_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_QUANTITY_MASK        0x0
#define NSMEQUITIES_ORDERS_QUANTITY_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_QUANTITY_SIZE        4

static unsigned
parse_nsmequities_orders_quantity(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_quantity, tvb, offset, NSMEQUITIES_ORDERS_QUANTITY_SIZE, NSMEQUITIES_ORDERS_QUANTITY_ENCODING);

    return offset + NSMEQUITIES_ORDERS_QUANTITY_SIZE;
}

/* Quantity Prevented From Trading */
#define NSMEQUITIES_ORDERS_QUANTITY_PREVENTED_FROM_TRADING_NAME        "Quantity Prevented From Trading"
#define NSMEQUITIES_ORDERS_QUANTITY_PREVENTED_FROM_TRADING_DESCRIPTION "Shares that would have executed if the trade would have occurred. Depending on AIQ type and the sizes of orders in question the value for this field could either be the same or different than the Decrement Shares field. For “Decrement both” they are always the same. For “Cancel oldest” they will be different if the incoming order is smaller than the resting order."
#define NSMEQUITIES_ORDERS_QUANTITY_PREVENTED_FROM_TRADING_FILTER      "nsmequities.orders.quantitypreventedfromtrading"
#define NSMEQUITIES_ORDERS_QUANTITY_PREVENTED_FROM_TRADING_TYPE        FT_UINT32
#define NSMEQUITIES_ORDERS_QUANTITY_PREVENTED_FROM_TRADING_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_QUANTITY_PREVENTED_FROM_TRADING_MASK        0x0
#define NSMEQUITIES_ORDERS_QUANTITY_PREVENTED_FROM_TRADING_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_QUANTITY_PREVENTED_FROM_TRADING_SIZE        4

static unsigned
parse_nsmequities_orders_quantity_prevented_from_trading(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_quantity_prevented_from_trading, tvb, offset, NSMEQUITIES_ORDERS_QUANTITY_PREVENTED_FROM_TRADING_SIZE, NSMEQUITIES_ORDERS_QUANTITY_PREVENTED_FROM_TRADING_ENCODING);

    return offset + NSMEQUITIES_ORDERS_QUANTITY_PREVENTED_FROM_TRADING_SIZE;
}

/* Random Reserves */
#define NSMEQUITIES_ORDERS_RANDOM_RESERVES_NAME        "Random Reserves"
#define NSMEQUITIES_ORDERS_RANDOM_RESERVES_DESCRIPTION "Shares to do random reserve with."
#define NSMEQUITIES_ORDERS_RANDOM_RESERVES_FILTER      "nsmequities.orders.randomreserves"
#define NSMEQUITIES_ORDERS_RANDOM_RESERVES_TYPE        FT_UINT32
#define NSMEQUITIES_ORDERS_RANDOM_RESERVES_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_RANDOM_RESERVES_MASK        0x0
#define NSMEQUITIES_ORDERS_RANDOM_RESERVES_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_RANDOM_RESERVES_SIZE        4

static unsigned
parse_nsmequities_orders_random_reserves(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_random_reserves, tvb, offset, NSMEQUITIES_ORDERS_RANDOM_RESERVES_SIZE, NSMEQUITIES_ORDERS_RANDOM_RESERVES_ENCODING);

    return offset + NSMEQUITIES_ORDERS_RANDOM_RESERVES_SIZE;
}

/* Reason */
#define NSMEQUITIES_ORDERS_REASON_NAME        "Reason"
#define NSMEQUITIES_ORDERS_REASON_DESCRIPTION "Only value currently allowed is: N = Adjusted to NAV"
#define NSMEQUITIES_ORDERS_REASON_FILTER      "nsmequities.orders.reason"
#define NSMEQUITIES_ORDERS_REASON_TYPE        FT_CHAR
#define NSMEQUITIES_ORDERS_REASON_DISPLAY     BASE_HEX
#define NSMEQUITIES_ORDERS_REASON_MASK        0x0
#define NSMEQUITIES_ORDERS_REASON_ENCODING    ENC_ASCII
#define NSMEQUITIES_ORDERS_REASON_SIZE        1

static const value_string nsmequities_orders_reason_vals[] = {
    { 'N', "Adjusted To Nav" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_reason(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_reason, tvb, offset, NSMEQUITIES_ORDERS_REASON_SIZE, NSMEQUITIES_ORDERS_REASON_ENCODING);

    return offset + NSMEQUITIES_ORDERS_REASON_SIZE;
}

/* Reference Price */
#define NSMEQUITIES_ORDERS_REFERENCE_PRICE_NAME        "Reference Price"
#define NSMEQUITIES_ORDERS_REFERENCE_PRICE_DESCRIPTION "The reference price associated with the execution"
#define NSMEQUITIES_ORDERS_REFERENCE_PRICE_FILTER      "nsmequities.orders.referenceprice"
#define NSMEQUITIES_ORDERS_REFERENCE_PRICE_TYPE        FT_UINT32
#define NSMEQUITIES_ORDERS_REFERENCE_PRICE_DISPLAY     BASE_CUSTOM
#define NSMEQUITIES_ORDERS_REFERENCE_PRICE_MASK        0x0
#define NSMEQUITIES_ORDERS_REFERENCE_PRICE_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_REFERENCE_PRICE_SIZE        4

static unsigned
parse_nsmequities_orders_reference_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_reference_price, tvb, offset, NSMEQUITIES_ORDERS_REFERENCE_PRICE_SIZE, NSMEQUITIES_ORDERS_REFERENCE_PRICE_ENCODING);

    return offset + NSMEQUITIES_ORDERS_REFERENCE_PRICE_SIZE;
}

/* Reference Price Type */
#define NSMEQUITIES_ORDERS_REFERENCE_PRICE_TYPE_NAME        "Reference Price Type"
#define NSMEQUITIES_ORDERS_REFERENCE_PRICE_TYPE_DESCRIPTION "Only value currently supported is: I = Intraday Indicative Value"
#define NSMEQUITIES_ORDERS_REFERENCE_PRICE_TYPE_FILTER      "nsmequities.orders.referencepricetype"
#define NSMEQUITIES_ORDERS_REFERENCE_PRICE_TYPE_TYPE        FT_CHAR
#define NSMEQUITIES_ORDERS_REFERENCE_PRICE_TYPE_DISPLAY     BASE_HEX
#define NSMEQUITIES_ORDERS_REFERENCE_PRICE_TYPE_MASK        0x0
#define NSMEQUITIES_ORDERS_REFERENCE_PRICE_TYPE_ENCODING    ENC_ASCII
#define NSMEQUITIES_ORDERS_REFERENCE_PRICE_TYPE_SIZE        1

static const value_string nsmequities_orders_reference_price_type_vals[] = {
    { 'I', "Intraday Indicative Value" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_reference_price_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_reference_price_type, tvb, offset, NSMEQUITIES_ORDERS_REFERENCE_PRICE_TYPE_SIZE, NSMEQUITIES_ORDERS_REFERENCE_PRICE_TYPE_ENCODING);

    return offset + NSMEQUITIES_ORDERS_REFERENCE_PRICE_TYPE_SIZE;
}

/* Reject Reason Code */
#define NSMEQUITIES_ORDERS_REJECT_REASON_CODE_NAME        "Reject Reason Code"
#define NSMEQUITIES_ORDERS_REJECT_REASON_CODE_DESCRIPTION "Login Reject Codes"
#define NSMEQUITIES_ORDERS_REJECT_REASON_CODE_FILTER      "nsmequities.orders.rejectreasoncode"
#define NSMEQUITIES_ORDERS_REJECT_REASON_CODE_TYPE        FT_CHAR
#define NSMEQUITIES_ORDERS_REJECT_REASON_CODE_DISPLAY     BASE_HEX
#define NSMEQUITIES_ORDERS_REJECT_REASON_CODE_MASK        0x0
#define NSMEQUITIES_ORDERS_REJECT_REASON_CODE_ENCODING    ENC_ASCII
#define NSMEQUITIES_ORDERS_REJECT_REASON_CODE_SIZE        1

static const value_string nsmequities_orders_reject_reason_code_vals[] = {
    { 'A', "Not Authorized" },
    { 'S', "Session Not Available" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_reject_reason_code(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_reject_reason_code, tvb, offset, NSMEQUITIES_ORDERS_REJECT_REASON_CODE_SIZE, NSMEQUITIES_ORDERS_REJECT_REASON_CODE_ENCODING);

    return offset + NSMEQUITIES_ORDERS_REJECT_REASON_CODE_SIZE;
}

/* Rejected Order Optional Field values the dispatch switches on */
#define NSMEQUITIES_ORDERS_REJECTED_ORDER_OPTIONAL_FIELD_USERREFIDX 28

/* Rejected Order Optional Field */
#define NSMEQUITIES_ORDERS_REJECTED_ORDER_OPTIONAL_FIELD_NAME        "Rejected Order Optional Field"
#define NSMEQUITIES_ORDERS_REJECTED_ORDER_OPTIONAL_FIELD_DESCRIPTION "Appendage Id"
#define NSMEQUITIES_ORDERS_REJECTED_ORDER_OPTIONAL_FIELD_FILTER      "nsmequities.orders.rejectedorderoptionalfield"
#define NSMEQUITIES_ORDERS_REJECTED_ORDER_OPTIONAL_FIELD_TYPE        FT_UINT8
#define NSMEQUITIES_ORDERS_REJECTED_ORDER_OPTIONAL_FIELD_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_REJECTED_ORDER_OPTIONAL_FIELD_MASK        0x0
#define NSMEQUITIES_ORDERS_REJECTED_ORDER_OPTIONAL_FIELD_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_REJECTED_ORDER_OPTIONAL_FIELD_SIZE        1

static const value_string nsmequities_orders_rejected_order_optional_field_vals[] = {
    { NSMEQUITIES_ORDERS_REJECTED_ORDER_OPTIONAL_FIELD_USERREFIDX, "UserRefIdx" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_rejected_order_optional_field(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_rejected_order_optional_field, tvb, offset, NSMEQUITIES_ORDERS_REJECTED_ORDER_OPTIONAL_FIELD_SIZE, NSMEQUITIES_ORDERS_REJECTED_ORDER_OPTIONAL_FIELD_ENCODING);

    return offset + NSMEQUITIES_ORDERS_REJECTED_ORDER_OPTIONAL_FIELD_SIZE;
}

/* Rejected Order Reason */
#define NSMEQUITIES_ORDERS_REJECTED_ORDER_REASON_NAME        "Rejected Order Reason"
#define NSMEQUITIES_ORDERS_REJECTED_ORDER_REASON_DESCRIPTION "The reason the order was rejected."
#define NSMEQUITIES_ORDERS_REJECTED_ORDER_REASON_FILTER      "nsmequities.orders.rejectedorderreason"
#define NSMEQUITIES_ORDERS_REJECTED_ORDER_REASON_TYPE        FT_UINT16
#define NSMEQUITIES_ORDERS_REJECTED_ORDER_REASON_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_REJECTED_ORDER_REASON_MASK        0x0
#define NSMEQUITIES_ORDERS_REJECTED_ORDER_REASON_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_REJECTED_ORDER_REASON_SIZE        2

static const value_string nsmequities_orders_rejected_order_reason_vals[] = {
    { 0x0001, "Quote Unavailable" },
    { 0x0002, "Destination Closed" },
    { 0x0003, "Invalid Display" },
    { 0x0004, "Invalid Max Floor" },
    { 0x0005, "Invalid Peg Type" },
    { 0x0006, "Fat Finger" },
    { 0x0007, "Halted" },
    { 0x0008, "Iso Not Allowed" },
    { 0x0009, "Invalid Side" },
    { 0x000A, "Processing Error" },
    { 0x000B, "Cancel Pending" },
    { 0x000C, "Firm Not Authorized" },
    { 0x000D, "Invalid Min Quantity" },
    { 0x000E, "No Closing Reference Price" },
    { 0x000F, "Other" },
    { 0x0010, "Cancel Not Allowed" },
    { 0x0011, "Pegging Not Allowed" },
    { 0x0012, "Crossed Market" },
    { 0x0013, "Invalid Quantity" },
    { 0x0014, "Invalid Cross Order" },
    { 0x0015, "Replace Not Allowed" },
    { 0x0016, "Routing Not Allowed" },
    { 0x0017, "Invalid Symbol" },
    { 0x0018, "Test" },
    { 0x0019, "Late Loc Too Aggressive" },
    { 0x001A, "Retail Not Allowed" },
    { 0x001B, "Invalid Midpoint Post Only Price" },
    { 0x001C, "Invalid Destination" },
    { 0x001D, "Invalid Price" },
    { 0x001E, "Shares Exceed Threshold" },
    { 0x001F, "Exceeds Maximum Allowed Notional Value" },
    { 0x0020, "Risk Aggregate Exposure Exceeded" },
    { 0x0021, "Risk Market Impact" },
    { 0x0022, "Risk Restricted Stock" },
    { 0x0023, "Risk Short Sell Restricted" },
    { 0x0024, "Risk Iso Not Allowed" },
    { 0x0025, "Risk Exceeds Adv Limit" },
    { 0x0026, "Risk Fat Finger" },
    { 0x0027, "Risk Locate Required" },
    { 0x0028, "Risk Symbol Message Rate Restriction" },
    { 0x0029, "Risk Port Message Rate Restriction" },
    { 0x002A, "Risk Duplicate Message Rate Restriction" },
    { 0x002B, "Risk Short Sell Not Allowed" },
    { 0x002C, "Risk Market Order Not Allowed" },
    { 0x002D, "Risk Pre Market Not Allowed" },
    { 0x002E, "Risk Post Market Not Allowed" },
    { 0x002F, "Risk Short Sell Exempt Not Allowed" },
    { 0x0030, "Risk Single Order Notional Exceeded" },
    { 0x0031, "Risk Max Quantity Exceeded" },
    { 0x0032, "Reg Sho State Not Available" },
    { 0x0033, "Risk Ipo Market Buy Not Allowed" },
    { 0x0040, "Invalid Aiq" },
    { 'T', "Test Mode" },
    { 'H', "Halted" },
    { 'Z', "Shares Exceeds Configured Safety Threshold" },
    { 'S', "Invalid Stock" },
    { 'D', "Invalid Display Type" },
    { 'C', "Nasdaq Is Closed" },
    { 'L', "Requested Firm Not Authorized For Requested Clearing Type On This Account" },
    { 'M', "Outside Of Permitted Times" },
    { 'R', "This Order Is Not Allowed In This Type Of Cross" },
    { 'X', "Invalid Price" },
    { 'N', "Invalid Minimum" },
    { 'O', "Other" },
    { 'W', "Invalid Midpoint" },
    { 'o', "There Is No Reference Price" },
    { 'q', "Midpoint Peg Orders Are Not Accepted" },
    { 'u', "Loc Order Priced More Aggressively" },
    { 'a', "Reject" },
    { 'b', "Easy To Borrow Etb" },
    { 'c', "Restricted" },
    { 'd', "Iso" },
    { 'e', "Odd" },
    { 'f', "Mid Point" },
    { 'g', "Pre Market" },
    { 'h', "Post Market" },
    { 'i', "Short Sale" },
    { 'j', "On Open" },
    { 'k', "On Close" },
    { 'l', "Two Sided" },
    { 'm', "Exceeded Shares Limit" },
    { 'n', "Exceeded Dollar Value Limit" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_rejected_order_reason(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_rejected_order_reason, tvb, offset, NSMEQUITIES_ORDERS_REJECTED_ORDER_REASON_SIZE, NSMEQUITIES_ORDERS_REJECTED_ORDER_REASON_ENCODING);

    return offset + NSMEQUITIES_ORDERS_REJECTED_ORDER_REASON_SIZE;
}

/* Rejected Order Reason V422018 */
#define NSMEQUITIES_ORDERS_REJECTED_ORDER_REASON_V422018_NAME        "Rejected Order Reason"
#define NSMEQUITIES_ORDERS_REJECTED_ORDER_REASON_V422018_DESCRIPTION "The reason the order was rejected. See currently supported Rejected Order Reasons below. Clients should anticipate additions to this list and thus support all capital letters of the English alphabet."
#define NSMEQUITIES_ORDERS_REJECTED_ORDER_REASON_V422018_FILTER      "nsmequities.orders.rejectedorderreason"
#define NSMEQUITIES_ORDERS_REJECTED_ORDER_REASON_V422018_TYPE        FT_CHAR
#define NSMEQUITIES_ORDERS_REJECTED_ORDER_REASON_V422018_DISPLAY     BASE_HEX
#define NSMEQUITIES_ORDERS_REJECTED_ORDER_REASON_V422018_MASK        0x0
#define NSMEQUITIES_ORDERS_REJECTED_ORDER_REASON_V422018_ENCODING    ENC_ASCII
#define NSMEQUITIES_ORDERS_REJECTED_ORDER_REASON_V422018_SIZE        1

static const value_string nsmequities_orders_rejected_order_reason_v422018_vals[] = {
    { 0x0001, "Quote Unavailable" },
    { 0x0002, "Destination Closed" },
    { 0x0003, "Invalid Display" },
    { 0x0004, "Invalid Max Floor" },
    { 0x0005, "Invalid Peg Type" },
    { 0x0006, "Fat Finger" },
    { 0x0007, "Halted" },
    { 0x0008, "Iso Not Allowed" },
    { 0x0009, "Invalid Side" },
    { 0x000A, "Processing Error" },
    { 0x000B, "Cancel Pending" },
    { 0x000C, "Firm Not Authorized" },
    { 0x000D, "Invalid Min Quantity" },
    { 0x000E, "No Closing Reference Price" },
    { 0x000F, "Other" },
    { 0x0010, "Cancel Not Allowed" },
    { 0x0011, "Pegging Not Allowed" },
    { 0x0012, "Crossed Market" },
    { 0x0013, "Invalid Quantity" },
    { 0x0014, "Invalid Cross Order" },
    { 0x0015, "Replace Not Allowed" },
    { 0x0016, "Routing Not Allowed" },
    { 0x0017, "Invalid Symbol" },
    { 0x0018, "Test" },
    { 0x0019, "Late Loc Too Aggressive" },
    { 0x001A, "Retail Not Allowed" },
    { 0x001B, "Invalid Midpoint Post Only Price" },
    { 0x001C, "Invalid Destination" },
    { 0x001D, "Invalid Price" },
    { 0x001E, "Shares Exceed Threshold" },
    { 0x001F, "Exceeds Maximum Allowed Notional Value" },
    { 0x0020, "Risk Aggregate Exposure Exceeded" },
    { 0x0021, "Risk Market Impact" },
    { 0x0022, "Risk Restricted Stock" },
    { 0x0023, "Risk Short Sell Restricted" },
    { 0x0024, "Risk Iso Not Allowed" },
    { 0x0025, "Risk Exceeds Adv Limit" },
    { 0x0026, "Risk Fat Finger" },
    { 0x0027, "Risk Locate Required" },
    { 0x0028, "Risk Symbol Message Rate Restriction" },
    { 0x0029, "Risk Port Message Rate Restriction" },
    { 0x002A, "Risk Duplicate Message Rate Restriction" },
    { 0x002B, "Risk Short Sell Not Allowed" },
    { 0x002C, "Risk Market Order Not Allowed" },
    { 0x002D, "Risk Pre Market Not Allowed" },
    { 0x002E, "Risk Post Market Not Allowed" },
    { 0x002F, "Risk Short Sell Exempt Not Allowed" },
    { 0x0030, "Risk Single Order Notional Exceeded" },
    { 0x0031, "Risk Max Quantity Exceeded" },
    { 0x0032, "Reg Sho State Not Available" },
    { 0x0033, "Risk Ipo Market Buy Not Allowed" },
    { 0x0040, "Invalid Aiq" },
    { 'T', "Test Mode" },
    { 'H', "Halted" },
    { 'Z', "Shares Exceeds Configured Safety Threshold" },
    { 'S', "Invalid Stock" },
    { 'D', "Invalid Display Type" },
    { 'C', "Nasdaq Is Closed" },
    { 'L', "Requested Firm Not Authorized For Requested Clearing Type On This Account" },
    { 'M', "Outside Of Permitted Times" },
    { 'R', "This Order Is Not Allowed In This Type Of Cross" },
    { 'X', "Invalid Price" },
    { 'N', "Invalid Minimum" },
    { 'O', "Other" },
    { 'W', "Invalid Midpoint" },
    { 'o', "There Is No Reference Price" },
    { 'q', "Midpoint Peg Orders Are Not Accepted" },
    { 'u', "Loc Order Priced More Aggressively" },
    { 'a', "Reject" },
    { 'b', "Easy To Borrow Etb" },
    { 'c', "Restricted" },
    { 'd', "Iso" },
    { 'e', "Odd" },
    { 'f', "Mid Point" },
    { 'g', "Pre Market" },
    { 'h', "Post Market" },
    { 'i', "Short Sale" },
    { 'j', "On Open" },
    { 'k', "On Close" },
    { 'l', "Two Sided" },
    { 'm', "Exceeded Shares Limit" },
    { 'n', "Exceeded Dollar Value Limit" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_rejected_order_reason_v422018(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_rejected_order_reason_v422018, tvb, offset, NSMEQUITIES_ORDERS_REJECTED_ORDER_REASON_V422018_SIZE, NSMEQUITIES_ORDERS_REJECTED_ORDER_REASON_V422018_ENCODING);

    return offset + NSMEQUITIES_ORDERS_REJECTED_ORDER_REASON_V422018_SIZE;
}

/* Replace Order Optional Field values the dispatch switches on */
#define NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_MINQTY              3
#define NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_MAXFLOOR            5
#define NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_PRICETYPE           6
#define NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_POSTONLY            12
#define NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_EXPIRETIME          15
#define NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_TRADENOW            16
#define NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_HANDLEINST          17
#define NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_RANDOMRESERVES      13
#define NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_PEGOFFSET           7
#define NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_DISCRETIONPRICE     9
#define NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_DISCRETIONPRICETYPE 10
#define NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_DISCRETIONPEGOFFSET 11
#define NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_SHARES_LOCATED      25
#define NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_LOCATE_BROKER       26
#define NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_USERREFIDX          28
#define NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_SIDE                27
#define NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_AIQ_STRATEGY        29
#define NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_AIQ_GROUP_ID        30

/* Replace Order Optional Field */
#define NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_NAME        "Replace Order Optional Field"
#define NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_DESCRIPTION "Appendage Id"
#define NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_FILTER      "nsmequities.orders.replaceorderoptionalfield"
#define NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_TYPE        FT_UINT8
#define NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_MASK        0x0
#define NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_SIZE        1

static const value_string nsmequities_orders_replace_order_optional_field_vals[] = {
    { NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_MINQTY, "MinQty" },
    { NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_MAXFLOOR, "MaxFloor" },
    { NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_PRICETYPE, "PriceType" },
    { NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_POSTONLY, "PostOnly" },
    { NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_EXPIRETIME, "ExpireTime" },
    { NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_TRADENOW, "TradeNow" },
    { NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_HANDLEINST, "HandleInst" },
    { NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_RANDOMRESERVES, "RandomReserves" },
    { NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_PEGOFFSET, "PegOffset" },
    { NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_DISCRETIONPRICE, "DiscretionPrice" },
    { NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_DISCRETIONPRICETYPE, "DiscretionPriceType" },
    { NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_DISCRETIONPEGOFFSET, "DiscretionPegOffset" },
    { NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_SHARES_LOCATED, "Shares Located" },
    { NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_LOCATE_BROKER, "Locate Broker" },
    { NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_USERREFIDX, "UserRefIdx" },
    { NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_SIDE, "Side" },
    { NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_AIQ_STRATEGY, "AIQ Strategy" },
    { NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_AIQ_GROUP_ID, "AIQ Group ID" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_replace_order_optional_field(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_replace_order_optional_field, tvb, offset, NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_SIZE, NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_ENCODING);

    return offset + NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_SIZE;
}

/* Replaced Message Optional Field values the dispatch switches on */
#define NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_FIRM                 2
#define NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_MINQTY               3
#define NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_MAXFLOOR             5
#define NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_PRICETYPE            6
#define NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_POSTONLY             12
#define NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_EXPIRETIME           15
#define NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_TRADENOW             16
#define NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_HANDLEINST           17
#define NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_BBO_WEIGHT_INDICATOR 18
#define NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_USERREFIDX           28
#define NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_AIQ_STRATEGY         29
#define NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_AIQ_GROUP_ID         30

/* Replaced Message Optional Field */
#define NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_NAME        "Replaced Message Optional Field"
#define NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_DESCRIPTION "Appendage Id"
#define NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_FILTER      "nsmequities.orders.replacedmessageoptionalfield"
#define NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_TYPE        FT_UINT8
#define NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_MASK        0x0
#define NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_SIZE        1

static const value_string nsmequities_orders_replaced_message_optional_field_vals[] = {
    { NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_FIRM, "Firm" },
    { NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_MINQTY, "MinQty" },
    { NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_MAXFLOOR, "MaxFloor" },
    { NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_PRICETYPE, "PriceType" },
    { NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_POSTONLY, "PostOnly" },
    { NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_EXPIRETIME, "ExpireTime" },
    { NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_TRADENOW, "TradeNow" },
    { NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_HANDLEINST, "HandleInst" },
    { NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_BBO_WEIGHT_INDICATOR, "BBO Weight Indicator" },
    { NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_USERREFIDX, "UserRefIdx" },
    { NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_AIQ_STRATEGY, "AIQ Strategy" },
    { NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_AIQ_GROUP_ID, "AIQ Group ID" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_replaced_message_optional_field(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_replaced_message_optional_field, tvb, offset, NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_SIZE, NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_ENCODING);

    return offset + NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_SIZE;
}

/* Replacement Order Token */
#define NSMEQUITIES_ORDERS_REPLACEMENT_ORDER_TOKEN_NAME        "Replacement Order Token"
#define NSMEQUITIES_ORDERS_REPLACEMENT_ORDER_TOKEN_DESCRIPTION "The Replacement Order Token field as entered"
#define NSMEQUITIES_ORDERS_REPLACEMENT_ORDER_TOKEN_FILTER      "nsmequities.orders.replacementordertoken"
#define NSMEQUITIES_ORDERS_REPLACEMENT_ORDER_TOKEN_TYPE        FT_STRING
#define NSMEQUITIES_ORDERS_REPLACEMENT_ORDER_TOKEN_DISPLAY     BASE_NONE
#define NSMEQUITIES_ORDERS_REPLACEMENT_ORDER_TOKEN_MASK        0x0
#define NSMEQUITIES_ORDERS_REPLACEMENT_ORDER_TOKEN_ENCODING    ENC_ASCII
#define NSMEQUITIES_ORDERS_REPLACEMENT_ORDER_TOKEN_SIZE        14

static unsigned
parse_nsmequities_orders_replacement_order_token(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_replacement_order_token, tvb, offset, NSMEQUITIES_ORDERS_REPLACEMENT_ORDER_TOKEN_SIZE, NSMEQUITIES_ORDERS_REPLACEMENT_ORDER_TOKEN_ENCODING);

    return offset + NSMEQUITIES_ORDERS_REPLACEMENT_ORDER_TOKEN_SIZE;
}

/* Requested Sequence Number */
#define NSMEQUITIES_ORDERS_REQUESTED_SEQUENCE_NUMBER_NAME        "Requested Sequence Number"
#define NSMEQUITIES_ORDERS_REQUESTED_SEQUENCE_NUMBER_DESCRIPTION "Specifies the next sequence number in ASCII the client wants to receive upon connection, or 0 to start receiving the most recently generated message."
#define NSMEQUITIES_ORDERS_REQUESTED_SEQUENCE_NUMBER_FILTER      "nsmequities.orders.requestedsequencenumber"
#define NSMEQUITIES_ORDERS_REQUESTED_SEQUENCE_NUMBER_TYPE        FT_UINT64
#define NSMEQUITIES_ORDERS_REQUESTED_SEQUENCE_NUMBER_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_REQUESTED_SEQUENCE_NUMBER_MASK        0x0
#define NSMEQUITIES_ORDERS_REQUESTED_SEQUENCE_NUMBER_ENCODING    ENC_ASCII
#define NSMEQUITIES_ORDERS_REQUESTED_SEQUENCE_NUMBER_SIZE        20

static unsigned
parse_nsmequities_orders_requested_sequence_number(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    const char *text = (const char *)tvb_get_string_enc(pinfo->pool, tvb, offset, NSMEQUITIES_ORDERS_REQUESTED_SEQUENCE_NUMBER_SIZE, ENC_ASCII);

    uint64_t value = (uint64_t)strtoull(text, NULL, 10);

    proto_tree_add_uint64(tree, hf_nsmequities_orders_requested_sequence_number, tvb, offset, NSMEQUITIES_ORDERS_REQUESTED_SEQUENCE_NUMBER_SIZE, value);

    return offset + NSMEQUITIES_ORDERS_REQUESTED_SEQUENCE_NUMBER_SIZE;
}

/* Requested Session */
#define NSMEQUITIES_ORDERS_REQUESTED_SESSION_NAME        "Requested Session"
#define NSMEQUITIES_ORDERS_REQUESTED_SESSION_DESCRIPTION "Specifies the session the client would like to log into, or all blanks to log into the currently active session."
#define NSMEQUITIES_ORDERS_REQUESTED_SESSION_FILTER      "nsmequities.orders.requestedsession"
#define NSMEQUITIES_ORDERS_REQUESTED_SESSION_TYPE        FT_STRING
#define NSMEQUITIES_ORDERS_REQUESTED_SESSION_DISPLAY     BASE_NONE
#define NSMEQUITIES_ORDERS_REQUESTED_SESSION_MASK        0x0
#define NSMEQUITIES_ORDERS_REQUESTED_SESSION_ENCODING    ENC_ASCII
#define NSMEQUITIES_ORDERS_REQUESTED_SESSION_SIZE        10

static unsigned
parse_nsmequities_orders_requested_session(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_requested_session, tvb, offset, NSMEQUITIES_ORDERS_REQUESTED_SESSION_SIZE, NSMEQUITIES_ORDERS_REQUESTED_SESSION_ENCODING);

    return offset + NSMEQUITIES_ORDERS_REQUESTED_SESSION_SIZE;
}

/* Route */
#define NSMEQUITIES_ORDERS_ROUTE_NAME     "Route"
#define NSMEQUITIES_ORDERS_ROUTE_FILTER   "nsmequities.orders.route"
#define NSMEQUITIES_ORDERS_ROUTE_TYPE     FT_STRING
#define NSMEQUITIES_ORDERS_ROUTE_DISPLAY  BASE_NONE
#define NSMEQUITIES_ORDERS_ROUTE_MASK     0x0
#define NSMEQUITIES_ORDERS_ROUTE_ENCODING ENC_ASCII
#define NSMEQUITIES_ORDERS_ROUTE_SIZE     4

static unsigned
parse_nsmequities_orders_route(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_route, tvb, offset, NSMEQUITIES_ORDERS_ROUTE_SIZE, NSMEQUITIES_ORDERS_ROUTE_ENCODING);

    return offset + NSMEQUITIES_ORDERS_ROUTE_SIZE;
}

/* Secondary Ord Ref Num */
#define NSMEQUITIES_ORDERS_SECONDARY_ORD_REF_NUM_NAME        "Secondary Ord Ref Num"
#define NSMEQUITIES_ORDERS_SECONDARY_ORD_REF_NUM_DESCRIPTION "An alternative order reference number used when publishing the order on the Nasdaq market data feeds (identifying, for example, the displayed portion of a reserve order)"
#define NSMEQUITIES_ORDERS_SECONDARY_ORD_REF_NUM_FILTER      "nsmequities.orders.secondaryordrefnum"
#define NSMEQUITIES_ORDERS_SECONDARY_ORD_REF_NUM_TYPE        FT_UINT64
#define NSMEQUITIES_ORDERS_SECONDARY_ORD_REF_NUM_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_SECONDARY_ORD_REF_NUM_MASK        0x0
#define NSMEQUITIES_ORDERS_SECONDARY_ORD_REF_NUM_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_SECONDARY_ORD_REF_NUM_SIZE        8

static unsigned
parse_nsmequities_orders_secondary_ord_ref_num(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_secondary_ord_ref_num, tvb, offset, NSMEQUITIES_ORDERS_SECONDARY_ORD_REF_NUM_SIZE, NSMEQUITIES_ORDERS_SECONDARY_ORD_REF_NUM_ENCODING);

    return offset + NSMEQUITIES_ORDERS_SECONDARY_ORD_REF_NUM_SIZE;
}

/* Sequenced Message Type values the dispatch switches on */
#define NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_SYSTEM_EVENT                 'S'
#define NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_ORDER_ACCEPTED               'A'
#define NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_REPLACED                     'U'
#define NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_CANCELED                     'C'
#define NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_AIQ_CANCELED                 'D'
#define NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_ORDER_EXECUTED               'E'
#define NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_BROKEN_TRADE                 'B'
#define NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_REJECTED_ORDER               'J'
#define NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_CANCEL_PENDING               'P'
#define NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_CANCEL_REJECT                'I'
#define NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_ORDER_PRIORITY_UPDATE        'T'
#define NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_ORDER_MODIFIED               'M'
#define NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_ORDER_RESTATED               'R'
#define NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_ACCOUNT_QUERY_RESPONSE       'Q'
#define NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_MASS_CANCEL_RESPONSE         'X'
#define NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_DISABLE_ORDER_ENTRY_RESPONSE 'G'
#define NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_ENABLE_ORDER_ENTRY_RESPONSE  'K'
#define NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_TRADE_CORRECTION             'F'
#define NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_SEQUENCED_TRADE_NOW          'N'

/* Sequenced Message Type */
#define NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_NAME        "Sequenced Message Type"
#define NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_DESCRIPTION "Value identifying sequenced message type"
#define NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_FILTER      "nsmequities.orders.sequencedmessagetype"
#define NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_TYPE        FT_CHAR
#define NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_DISPLAY     BASE_HEX
#define NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_MASK        0x0
#define NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_ENCODING    ENC_ASCII
#define NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_SIZE        1

static const value_string nsmequities_orders_sequenced_message_type_vals[] = {
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_SYSTEM_EVENT, "System Event Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_ORDER_ACCEPTED, "Order Accepted Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_REPLACED, "Replaced Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_CANCELED, "Canceled Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_AIQ_CANCELED, "Aiq Canceled Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_ORDER_EXECUTED, "Order Executed Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_BROKEN_TRADE, "Broken Trade Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_REJECTED_ORDER, "Rejected Order Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_CANCEL_PENDING, "Cancel Pending Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_CANCEL_REJECT, "Cancel Reject Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_ORDER_PRIORITY_UPDATE, "Order Priority Update Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_ORDER_MODIFIED, "Order Modified Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_ORDER_RESTATED, "Order Restated Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_ACCOUNT_QUERY_RESPONSE, "Account Query Response Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_MASS_CANCEL_RESPONSE, "Mass Cancel Response Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_DISABLE_ORDER_ENTRY_RESPONSE, "Disable Order Entry Response Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_ENABLE_ORDER_ENTRY_RESPONSE, "Enable Order Entry Response Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_TRADE_CORRECTION, "Trade Correction Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_SEQUENCED_TRADE_NOW, "Sequenced Trade Now Message" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_sequenced_message_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_sequenced_message_type, tvb, offset, NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_SIZE, NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_ENCODING);

    return offset + NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_SIZE;
}

/* Server Packet Type values the dispatch switches on */
#define NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_DEBUG_PACKET            '+'
#define NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET   'A'
#define NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET   'J'
#define NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET   'S'
#define NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_SERVER_HEARTBEAT_PACKET 'H'
#define NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_END_OF_SESSION_PACKET   'Z'

/* Server Packet Type */
#define NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_NAME        "Packet Type"
#define NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_DESCRIPTION "Code identifying this packet type sent by the server"
#define NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_FILTER      "nsmequities.orders.serverpackettype"
#define NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_TYPE        FT_CHAR
#define NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_DISPLAY     BASE_HEX
#define NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_MASK        0x0
#define NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_ENCODING    ENC_ASCII
#define NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_SIZE        1

static const value_string nsmequities_orders_server_packet_type_vals[] = {
    { NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_DEBUG_PACKET, "Debug Packet" },
    { NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET, "Login Accepted Packet" },
    { NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET, "Login Rejected Packet" },
    { NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET, "Sequenced Data Packet" },
    { NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_SERVER_HEARTBEAT_PACKET, "Server Heartbeat Packet" },
    { NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_END_OF_SESSION_PACKET, "End Of Session Packet" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_server_packet_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_server_packet_type, tvb, offset, NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_SIZE, NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_ENCODING);

    return offset + NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_SIZE;
}

/* Shares */
#define NSMEQUITIES_ORDERS_SHARES_NAME        "Shares"
#define NSMEQUITIES_ORDERS_SHARES_DESCRIPTION "Total number of shares. Must be greater than zero and less than 1,000,000"
#define NSMEQUITIES_ORDERS_SHARES_FILTER      "nsmequities.orders.shares"
#define NSMEQUITIES_ORDERS_SHARES_TYPE        FT_UINT32
#define NSMEQUITIES_ORDERS_SHARES_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_SHARES_MASK        0x0
#define NSMEQUITIES_ORDERS_SHARES_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_SHARES_SIZE        4

static unsigned
parse_nsmequities_orders_shares(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_shares, tvb, offset, NSMEQUITIES_ORDERS_SHARES_SIZE, NSMEQUITIES_ORDERS_SHARES_ENCODING);

    return offset + NSMEQUITIES_ORDERS_SHARES_SIZE;
}

/* Shares Located */
#define NSMEQUITIES_ORDERS_SHARES_LOCATED_NAME        "Shares Located"
#define NSMEQUITIES_ORDERS_SHARES_LOCATED_DESCRIPTION "Shares located for short sale order"
#define NSMEQUITIES_ORDERS_SHARES_LOCATED_FILTER      "nsmequities.orders.shareslocated"
#define NSMEQUITIES_ORDERS_SHARES_LOCATED_TYPE        FT_CHAR
#define NSMEQUITIES_ORDERS_SHARES_LOCATED_DISPLAY     BASE_HEX
#define NSMEQUITIES_ORDERS_SHARES_LOCATED_MASK        0x0
#define NSMEQUITIES_ORDERS_SHARES_LOCATED_ENCODING    ENC_ASCII
#define NSMEQUITIES_ORDERS_SHARES_LOCATED_SIZE        1

static const value_string nsmequities_orders_shares_located_vals[] = {
    { 'Y', "Yes" },
    { 'N', "No" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_shares_located(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_shares_located, tvb, offset, NSMEQUITIES_ORDERS_SHARES_LOCATED_SIZE, NSMEQUITIES_ORDERS_SHARES_LOCATED_ENCODING);

    return offset + NSMEQUITIES_ORDERS_SHARES_LOCATED_SIZE;
}

/* Side */
#define NSMEQUITIES_ORDERS_SIDE_NAME     "Side"
#define NSMEQUITIES_ORDERS_SIDE_FILTER   "nsmequities.orders.side"
#define NSMEQUITIES_ORDERS_SIDE_TYPE     FT_CHAR
#define NSMEQUITIES_ORDERS_SIDE_DISPLAY  BASE_HEX
#define NSMEQUITIES_ORDERS_SIDE_MASK     0x0
#define NSMEQUITIES_ORDERS_SIDE_ENCODING ENC_ASCII
#define NSMEQUITIES_ORDERS_SIDE_SIZE     1

static const value_string nsmequities_orders_side_vals[] = {
    { 'B', "Buy" },
    { 'S', "Sell" },
    { 'T', "Sell Short" },
    { 'E', "Sell Short Exempt" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_side(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_side, tvb, offset, NSMEQUITIES_ORDERS_SIDE_SIZE, NSMEQUITIES_ORDERS_SIDE_ENCODING);

    return offset + NSMEQUITIES_ORDERS_SIDE_SIZE;
}

/* Stock */
#define NSMEQUITIES_ORDERS_STOCK_NAME        "Stock"
#define NSMEQUITIES_ORDERS_STOCK_DESCRIPTION "Stock Symbol"
#define NSMEQUITIES_ORDERS_STOCK_FILTER      "nsmequities.orders.stock"
#define NSMEQUITIES_ORDERS_STOCK_TYPE        FT_STRING
#define NSMEQUITIES_ORDERS_STOCK_DISPLAY     BASE_NONE
#define NSMEQUITIES_ORDERS_STOCK_MASK        0x0
#define NSMEQUITIES_ORDERS_STOCK_ENCODING    ENC_ASCII
#define NSMEQUITIES_ORDERS_STOCK_SIZE        8

static unsigned
parse_nsmequities_orders_stock(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_stock, tvb, offset, NSMEQUITIES_ORDERS_STOCK_SIZE, NSMEQUITIES_ORDERS_STOCK_ENCODING);

    return offset + NSMEQUITIES_ORDERS_STOCK_SIZE;
}

/* Symbol */
#define NSMEQUITIES_ORDERS_SYMBOL_NAME        "Symbol"
#define NSMEQUITIES_ORDERS_SYMBOL_DESCRIPTION "Stock Symbol"
#define NSMEQUITIES_ORDERS_SYMBOL_FILTER      "nsmequities.orders.symbol"
#define NSMEQUITIES_ORDERS_SYMBOL_TYPE        FT_STRING
#define NSMEQUITIES_ORDERS_SYMBOL_DISPLAY     BASE_NONE
#define NSMEQUITIES_ORDERS_SYMBOL_MASK        0x0
#define NSMEQUITIES_ORDERS_SYMBOL_ENCODING    ENC_ASCII
#define NSMEQUITIES_ORDERS_SYMBOL_SIZE        8

static unsigned
parse_nsmequities_orders_symbol(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_symbol, tvb, offset, NSMEQUITIES_ORDERS_SYMBOL_SIZE, NSMEQUITIES_ORDERS_SYMBOL_ENCODING);

    return offset + NSMEQUITIES_ORDERS_SYMBOL_SIZE;
}

/* Time In Force */
#define NSMEQUITIES_ORDERS_TIME_IN_FORCE_NAME        "Time In Force"
#define NSMEQUITIES_ORDERS_TIME_IN_FORCE_DESCRIPTION "Corresponds to TimeInForce (59) in Nasdaq FIX"
#define NSMEQUITIES_ORDERS_TIME_IN_FORCE_FILTER      "nsmequities.orders.timeinforce"
#define NSMEQUITIES_ORDERS_TIME_IN_FORCE_TYPE        FT_CHAR
#define NSMEQUITIES_ORDERS_TIME_IN_FORCE_DISPLAY     BASE_HEX
#define NSMEQUITIES_ORDERS_TIME_IN_FORCE_MASK        0x0
#define NSMEQUITIES_ORDERS_TIME_IN_FORCE_ENCODING    ENC_ASCII
#define NSMEQUITIES_ORDERS_TIME_IN_FORCE_SIZE        1

static const value_string nsmequities_orders_time_in_force_vals[] = {
    { '0', "Day" },
    { '3', "Ioc" },
    { '5', "Gtx Extended Hours" },
    { '6', "Gtt" },
    { 'E', "After Hours" },
    { 99998, "Market Hours" },
    { 99999, "System Hours" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_time_in_force(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_time_in_force, tvb, offset, NSMEQUITIES_ORDERS_TIME_IN_FORCE_SIZE, NSMEQUITIES_ORDERS_TIME_IN_FORCE_ENCODING);

    return offset + NSMEQUITIES_ORDERS_TIME_IN_FORCE_SIZE;
}

/* Time In Force V422018 */
#define NSMEQUITIES_ORDERS_TIME_IN_FORCE_V422018_NAME        "Time In Force"
#define NSMEQUITIES_ORDERS_TIME_IN_FORCE_V422018_DESCRIPTION "The number of seconds that this order should live before being automatically canceled. Special values for Time in Force are listed in Data Types above."
#define NSMEQUITIES_ORDERS_TIME_IN_FORCE_V422018_FILTER      "nsmequities.orders.timeinforce"
#define NSMEQUITIES_ORDERS_TIME_IN_FORCE_V422018_TYPE        FT_UINT32
#define NSMEQUITIES_ORDERS_TIME_IN_FORCE_V422018_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_TIME_IN_FORCE_V422018_MASK        0x0
#define NSMEQUITIES_ORDERS_TIME_IN_FORCE_V422018_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_TIME_IN_FORCE_V422018_SIZE        4

static const value_string nsmequities_orders_time_in_force_v422018_vals[] = {
    { 0, "Day" },
    { 3, "Ioc" },
    { 5, "Gtx Extended Hours" },
    { 6, "Gtt" },
    { 'E', "After Hours" },
    { 99998, "Market Hours" },
    { 99999, "System Hours" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_time_in_force_v422018(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_time_in_force_v422018, tvb, offset, NSMEQUITIES_ORDERS_TIME_IN_FORCE_V422018_SIZE, NSMEQUITIES_ORDERS_TIME_IN_FORCE_V422018_ENCODING);

    return offset + NSMEQUITIES_ORDERS_TIME_IN_FORCE_V422018_SIZE;
}

/* Timestamp */
#define NSMEQUITIES_ORDERS_TIMESTAMP_NAME        "Timestamp"
#define NSMEQUITIES_ORDERS_TIMESTAMP_DESCRIPTION "Expressed as nanoseconds since midnight"
#define NSMEQUITIES_ORDERS_TIMESTAMP_FILTER      "nsmequities.orders.timestamp"
#define NSMEQUITIES_ORDERS_TIMESTAMP_TYPE        FT_ABSOLUTE_TIME
#define NSMEQUITIES_ORDERS_TIMESTAMP_DISPLAY     ABSOLUTE_TIME_UTC
#define NSMEQUITIES_ORDERS_TIMESTAMP_MASK        0x0
#define NSMEQUITIES_ORDERS_TIMESTAMP_ENCODING    ENC_TIME_NSECS | ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_TIMESTAMP_SIZE        8

static unsigned
parse_nsmequities_orders_timestamp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    uint64_t counted = tvb_get_ntoh64(tvb, offset);

    if (!nsmequities_orders_pref_read_timestamp) {
        proto_tree_add_uint64(tree, hf_nsmequities_orders_elapsed_nanoseconds, tvb, offset, NSMEQUITIES_ORDERS_TIMESTAMP_SIZE, counted);

        return offset + NSMEQUITIES_ORDERS_TIMESTAMP_SIZE;
    }

    nstime_t time = {
        .secs = (time_t)(counted / 1000000000),
        .nsecs = (int)(counted % 1000000000) * 1,
    };

    nstime_t instant;

    nsmequities_orders_utc(pinfo, (uint64_t)time.secs, (uint32_t)time.nsecs, &instant);

    /* The instant reads unambiguously, the time of day it was sent at does not */
    proto_item *reading = proto_tree_add_time(tree, hf_nsmequities_orders_timestamp, tvb, offset, NSMEQUITIES_ORDERS_TIMESTAMP_SIZE, &instant);

    proto_tree *readings = proto_item_add_subtree(reading, ett_nsmequities_orders_timestamp);

    char clock[32];

    nsmequities_orders_time_of_day_label(clock, sizeof(clock), &time);

    proto_item_set_generated(proto_tree_add_time_format_value(readings, hf_nsmequities_orders_time_of_day, tvb, offset, NSMEQUITIES_ORDERS_TIMESTAMP_SIZE, &time, "%s", clock));
    proto_item_set_generated(proto_tree_add_time(readings, hf_nsmequities_orders_local, tvb, offset, NSMEQUITIES_ORDERS_TIMESTAMP_SIZE, &instant));
    proto_tree_add_uint64(readings, hf_nsmequities_orders_elapsed_nanoseconds, tvb, offset, NSMEQUITIES_ORDERS_TIMESTAMP_SIZE, counted);

    return offset + NSMEQUITIES_ORDERS_TIMESTAMP_SIZE;
}

/* Timestamp V422018 */
#define NSMEQUITIES_ORDERS_TIMESTAMP_V422018_NAME        "Timestamp"
#define NSMEQUITIES_ORDERS_TIMESTAMP_V422018_DESCRIPTION "Timestamp – reflected as the number of nanoseconds past midnight."
#define NSMEQUITIES_ORDERS_TIMESTAMP_V422018_FILTER      "nsmequities.orders.timestampv422018"
#define NSMEQUITIES_ORDERS_TIMESTAMP_V422018_TYPE        FT_UINT64
#define NSMEQUITIES_ORDERS_TIMESTAMP_V422018_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_TIMESTAMP_V422018_MASK        0x0
#define NSMEQUITIES_ORDERS_TIMESTAMP_V422018_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_TIMESTAMP_V422018_SIZE        8

static unsigned
parse_nsmequities_orders_timestamp_v422018(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_timestamp_v422018, tvb, offset, NSMEQUITIES_ORDERS_TIMESTAMP_V422018_SIZE, NSMEQUITIES_ORDERS_TIMESTAMP_V422018_ENCODING);

    return offset + NSMEQUITIES_ORDERS_TIMESTAMP_V422018_SIZE;
}

/* Trade Now */
#define NSMEQUITIES_ORDERS_TRADE_NOW_NAME        "Trade Now"
#define NSMEQUITIES_ORDERS_TRADE_NOW_DESCRIPTION "TradeNow"
#define NSMEQUITIES_ORDERS_TRADE_NOW_FILTER      "nsmequities.orders.tradenow"
#define NSMEQUITIES_ORDERS_TRADE_NOW_TYPE        FT_CHAR
#define NSMEQUITIES_ORDERS_TRADE_NOW_DISPLAY     BASE_HEX
#define NSMEQUITIES_ORDERS_TRADE_NOW_MASK        0x0
#define NSMEQUITIES_ORDERS_TRADE_NOW_ENCODING    ENC_ASCII
#define NSMEQUITIES_ORDERS_TRADE_NOW_SIZE        1

static const value_string nsmequities_orders_trade_now_vals[] = {
    { 'Y', "Yes" },
    { 'N', "No" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_trade_now(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_trade_now, tvb, offset, NSMEQUITIES_ORDERS_TRADE_NOW_SIZE, NSMEQUITIES_ORDERS_TRADE_NOW_ENCODING);

    return offset + NSMEQUITIES_ORDERS_TRADE_NOW_SIZE;
}

/* Unsequenced Message Type values the dispatch switches on */
#define NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_ENTER_ORDER                 'O'
#define NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_REPLACE_ORDER               'U'
#define NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_CANCEL_ORDER                'X'
#define NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_MODIFY_ORDER                'M'
#define NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_ACCOUNT_QUERY               'Q'
#define NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_MASS_CANCEL_REQUEST         'C'
#define NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_DISABLE_ORDER_ENTRY_REQUEST 'D'
#define NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_ENABLE_ORDER_ENTRY_REQUEST  'E'
#define NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_TRADE_NOW                   'N'

/* Unsequenced Message Type */
#define NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_NAME        "Unsequenced Message Type"
#define NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_DESCRIPTION "Value identifying unsequenced message type"
#define NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_FILTER      "nsmequities.orders.unsequencedmessagetype"
#define NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_TYPE        FT_CHAR
#define NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_DISPLAY     BASE_HEX
#define NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_MASK        0x0
#define NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_ENCODING    ENC_ASCII
#define NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_SIZE        1

static const value_string nsmequities_orders_unsequenced_message_type_vals[] = {
    { NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_ENTER_ORDER, "Enter Order Message" },
    { NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_REPLACE_ORDER, "Replace Order Message" },
    { NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_CANCEL_ORDER, "Cancel Order Message" },
    { NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_MODIFY_ORDER, "Modify Order Message" },
    { NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_ACCOUNT_QUERY, "Account Query Message" },
    { NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_MASS_CANCEL_REQUEST, "Mass Cancel Request Message" },
    { NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_DISABLE_ORDER_ENTRY_REQUEST, "Disable Order Entry Request Message" },
    { NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_ENABLE_ORDER_ENTRY_REQUEST, "Enable Order Entry Request Message" },
    { NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_TRADE_NOW, "Trade Now Message" },
    { 0, NULL }
};

static unsigned
parse_nsmequities_orders_unsequenced_message_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_unsequenced_message_type, tvb, offset, NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_SIZE, NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_ENCODING);

    return offset + NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_SIZE;
}

/* User Ref Idx */
#define NSMEQUITIES_ORDERS_USER_REF_IDX_NAME        "User Ref Idx"
#define NSMEQUITIES_ORDERS_USER_REF_IDX_DESCRIPTION "User Reference Index – identifies the channel within the given port"
#define NSMEQUITIES_ORDERS_USER_REF_IDX_FILTER      "nsmequities.orders.userrefidx"
#define NSMEQUITIES_ORDERS_USER_REF_IDX_TYPE        FT_UINT8
#define NSMEQUITIES_ORDERS_USER_REF_IDX_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_USER_REF_IDX_MASK        0x0
#define NSMEQUITIES_ORDERS_USER_REF_IDX_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_USER_REF_IDX_SIZE        1

static unsigned
parse_nsmequities_orders_user_ref_idx(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_user_ref_idx, tvb, offset, NSMEQUITIES_ORDERS_USER_REF_IDX_SIZE, NSMEQUITIES_ORDERS_USER_REF_IDX_ENCODING);

    return offset + NSMEQUITIES_ORDERS_USER_REF_IDX_SIZE;
}

/* User Ref Num */
#define NSMEQUITIES_ORDERS_USER_REF_NUM_NAME        "User Ref Num"
#define NSMEQUITIES_ORDERS_USER_REF_NUM_DESCRIPTION "UserRefNum must be day-unique and strictly increasing for each OUCH account."
#define NSMEQUITIES_ORDERS_USER_REF_NUM_FILTER      "nsmequities.orders.userrefnum"
#define NSMEQUITIES_ORDERS_USER_REF_NUM_TYPE        FT_UINT32
#define NSMEQUITIES_ORDERS_USER_REF_NUM_DISPLAY     BASE_DEC
#define NSMEQUITIES_ORDERS_USER_REF_NUM_MASK        0x0
#define NSMEQUITIES_ORDERS_USER_REF_NUM_ENCODING    ENC_BIG_ENDIAN
#define NSMEQUITIES_ORDERS_USER_REF_NUM_SIZE        4

static unsigned
parse_nsmequities_orders_user_ref_num(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_user_ref_num, tvb, offset, NSMEQUITIES_ORDERS_USER_REF_NUM_SIZE, NSMEQUITIES_ORDERS_USER_REF_NUM_ENCODING);

    return offset + NSMEQUITIES_ORDERS_USER_REF_NUM_SIZE;
}

/* Username */
#define NSMEQUITIES_ORDERS_USERNAME_NAME        "Username"
#define NSMEQUITIES_ORDERS_USERNAME_DESCRIPTION "Session username"
#define NSMEQUITIES_ORDERS_USERNAME_FILTER      "nsmequities.orders.username"
#define NSMEQUITIES_ORDERS_USERNAME_TYPE        FT_STRING
#define NSMEQUITIES_ORDERS_USERNAME_DISPLAY     BASE_NONE
#define NSMEQUITIES_ORDERS_USERNAME_MASK        0x0
#define NSMEQUITIES_ORDERS_USERNAME_ENCODING    ENC_ASCII
#define NSMEQUITIES_ORDERS_USERNAME_SIZE        6

static unsigned
parse_nsmequities_orders_username(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_nsmequities_orders_username, tvb, offset, NSMEQUITIES_ORDERS_USERNAME_SIZE, NSMEQUITIES_ORDERS_USERNAME_ENCODING);

    return offset + NSMEQUITIES_ORDERS_USERNAME_SIZE;
}

/*
 * NsmEquities Orders Structs
 */

/* Message and group dissect methods */
static unsigned dissect_nsmequities_orders_client_packet_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_debug_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_login_request_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_unsequenced_data_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_enter_order(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_enter_order_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size);
static unsigned dissect_nsmequities_orders_replace_order(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_replace_order_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size);
static unsigned dissect_nsmequities_orders_cancel_order(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_cancel_order_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size);
static unsigned dissect_nsmequities_orders_modify_order(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_modify_order_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size);
static unsigned dissect_nsmequities_orders_account_query(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_account_query_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size);
static unsigned dissect_nsmequities_orders_mass_cancel_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_mass_cancel_request_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size);
static unsigned dissect_nsmequities_orders_disable_order_entry_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_disable_order_entry_request_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size);
static unsigned dissect_nsmequities_orders_enable_order_entry_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_enable_order_entry_request_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size);
static unsigned dissect_nsmequities_orders_server_packet_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_login_accepted_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_login_rejected_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_sequenced_data_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_system_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_order_accepted(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_order_accepted_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size);
static unsigned dissect_nsmequities_orders_replaced(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_replaced_message_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size);
static unsigned dissect_nsmequities_orders_canceled(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_canceled_message_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size);
static unsigned dissect_nsmequities_orders_aiq_canceled(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_aiq_canceled_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size);
static unsigned dissect_nsmequities_orders_order_executed(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_order_executed_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size);
static unsigned dissect_nsmequities_orders_broken_trade(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_broken_trade_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size);
static unsigned dissect_nsmequities_orders_rejected_order(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_rejected_order_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size);
static unsigned dissect_nsmequities_orders_cancel_pending(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_cancel_pending_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size);
static unsigned dissect_nsmequities_orders_cancel_reject(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_cancel_reject_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size);
static unsigned dissect_nsmequities_orders_order_priority_update(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_order_priority_update_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size);
static unsigned dissect_nsmequities_orders_order_modified(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_order_modified_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size);
static unsigned dissect_nsmequities_orders_order_restated(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_order_restated_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size);
static unsigned dissect_nsmequities_orders_account_query_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_account_query_response_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size);
static unsigned dissect_nsmequities_orders_mass_cancel_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_mass_cancel_response_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size);
static unsigned dissect_nsmequities_orders_disable_order_entry_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_disable_order_entry_response_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size);
static unsigned dissect_nsmequities_orders_enable_order_entry_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_enable_order_entry_response_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size);
static unsigned dissect_nsmequities_orders_unsequenced_data_packet_v422018(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_enter_order_v422018(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_replace_order_v422018(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_cancel_order_v422018(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_modify_order_v422018(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_trade_now(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_sequenced_data_packet_v422018(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_system_event_v422018(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_accepted(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_replaced_v422018(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_canceled_v422018(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_aiq_cancelled(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_executed(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_broken_trade_v422018(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_executed_with_reference_price(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_trade_correction(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_rejected_order_v422018(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_cancel_pending_v422018(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_cancel_reject_v422018(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_order_priority_update_v422018(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_order_modified_v422018(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_sequenced_trade_now(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_nsmequities_orders_client_packet_client_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t client_packet_type);
static unsigned dissect_nsmequities_orders_client_packet_client_payload_v422018(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t client_packet_type);
static unsigned dissect_nsmequities_orders_unsequenced_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t unsequenced_message_type);
static unsigned dissect_nsmequities_orders_unsequenced_message_v422018(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t unsequenced_message_type);
static unsigned dissect_nsmequities_orders_enter_order_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t enter_order_optional_field);
static unsigned dissect_nsmequities_orders_replace_order_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t replace_order_optional_field);
static unsigned dissect_nsmequities_orders_cancel_order_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t cancel_order_optional_field);
static unsigned dissect_nsmequities_orders_modify_order_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t modify_order_optional_field);
static unsigned dissect_nsmequities_orders_account_query_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t account_query_optional_field);
static unsigned dissect_nsmequities_orders_mass_cancel_request_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t mass_cancel_request_optional_field);
static unsigned dissect_nsmequities_orders_disable_order_entry_request_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t disable_order_entry_request_optional_field);
static unsigned dissect_nsmequities_orders_enable_order_entry_request_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t enable_order_entry_request_optional_field);
static unsigned dissect_nsmequities_orders_server_packet_server_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t server_packet_type);
static unsigned dissect_nsmequities_orders_server_packet_server_payload_v422018(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t server_packet_type);
static unsigned dissect_nsmequities_orders_sequenced_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t sequenced_message_type);
static unsigned dissect_nsmequities_orders_sequenced_message_v422018(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t sequenced_message_type);
static unsigned dissect_nsmequities_orders_order_accepted_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t order_accepted_optional_field);
static unsigned dissect_nsmequities_orders_replaced_message_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t replaced_message_optional_field);
static unsigned dissect_nsmequities_orders_canceled_message_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t canceled_message_optional_field);
static unsigned dissect_nsmequities_orders_aiq_canceled_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t aiq_canceled_optional_field);
static unsigned dissect_nsmequities_orders_order_executed_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t order_executed_optional_field);
static unsigned dissect_nsmequities_orders_broken_trade_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t broken_trade_optional_field);
static unsigned dissect_nsmequities_orders_rejected_order_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t rejected_order_optional_field);
static unsigned dissect_nsmequities_orders_cancel_pending_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t cancel_pending_optional_field);
static unsigned dissect_nsmequities_orders_cancel_reject_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t cancel_reject_optional_field);
static unsigned dissect_nsmequities_orders_order_priority_update_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t order_priority_update_optional_field);
static unsigned dissect_nsmequities_orders_order_modified_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t order_modified_optional_field);
static unsigned dissect_nsmequities_orders_order_restated_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t order_restated_optional_field);
static unsigned dissect_nsmequities_orders_account_query_response_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t account_query_response_optional_field);
static unsigned dissect_nsmequities_orders_mass_cancel_response_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t mass_cancel_response_optional_field);
static unsigned dissect_nsmequities_orders_disable_order_entry_response_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t disable_order_entry_response_optional_field);
static unsigned dissect_nsmequities_orders_enable_order_entry_response_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t enable_order_entry_response_optional_field);

/* Client Packet Header */
static unsigned
dissect_nsmequities_orders_client_packet_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (nsmequities_orders_show_headers) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nsmequities_orders_client_packet_header, &item, "Client Packet Header");
    }

    unsigned start = offset;

    offset = parse_nsmequities_orders_packet_length(tvb, pinfo, group, offset);
    offset = parse_nsmequities_orders_client_packet_type(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Debug Packet */
static unsigned
dissect_nsmequities_orders_debug_packet(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, unsigned offset)
{
    /* Debug Text is a placeholder, it consumes no bytes */

    return offset;
}

/* Login Request Packet */
static unsigned
dissect_nsmequities_orders_login_request_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_orders_username(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_password(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_requested_session(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_requested_sequence_number(tvb, pinfo, tree, offset);

    return offset;
}

/* Unsequenced Data Packet */
static unsigned
dissect_nsmequities_orders_unsequenced_data_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;

    offset = parse_nsmequities_orders_unsequenced_message_type(tvb, pinfo, tree, offset);

    uint32_t unsequenced_message_type = tvb_get_uint8(tvb, start);

    offset = dissect_nsmequities_orders_unsequenced_message(tvb, pinfo, tree, offset, unsequenced_message_type);

    return offset;
}

/* Enter Order Message */
static unsigned
dissect_nsmequities_orders_enter_order(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;

    offset = parse_nsmequities_orders_user_ref_num(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_side(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_quantity(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_symbol(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_price(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_time_in_force(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_display(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_capacity(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_inter_market_sweep_eligibility(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_cross_type(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_clordid(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_appendage_length(tvb, pinfo, tree, offset);

    /* Enter Order Appendage: spans Appendage Length from here */
    uint32_t enter_order_appendage = tvb_get_ntohs(tvb, start + 44);

    offset = dissect_nsmequities_orders_enter_order_appendage(tvb, pinfo, tree, offset, enter_order_appendage);

    return offset;
}

/* Enter Order Appendage */
static unsigned
dissect_nsmequities_orders_enter_order_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (nsmequities_orders_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nsmequities_orders_enter_order_appendage, &item, "Enter Order Appendage");
    }

    unsigned start = offset;

    unsigned end = offset + size;

    while (offset < end) {
        unsigned entry = offset;
        unsigned consumed = tvb_get_uint8(tvb, entry) + 1;

        offset = parse_nsmequities_orders_optional_field_length(tvb, pinfo, group, offset);
        offset = parse_nsmequities_orders_enter_order_optional_field(tvb, pinfo, group, offset);

        uint32_t enter_order_optional_field = tvb_get_uint8(tvb, entry + 1);

        offset = dissect_nsmequities_orders_enter_order_optional_value(tvb, pinfo, group, offset, enter_order_optional_field);

        offset = entry + consumed;
    }

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Replace Order Message */
static unsigned
dissect_nsmequities_orders_replace_order(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;

    offset = parse_nsmequities_orders_orig_user_ref_num(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_user_ref_num(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_quantity(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_price(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_time_in_force(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_display(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_inter_market_sweep_eligibility(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_clordid(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_appendage_length(tvb, pinfo, tree, offset);

    /* Replace Order Appendage: spans Appendage Length from here */
    uint32_t replace_order_appendage = tvb_get_ntohs(tvb, start + 37);

    offset = dissect_nsmequities_orders_replace_order_appendage(tvb, pinfo, tree, offset, replace_order_appendage);

    return offset;
}

/* Replace Order Appendage */
static unsigned
dissect_nsmequities_orders_replace_order_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (nsmequities_orders_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nsmequities_orders_replace_order_appendage, &item, "Replace Order Appendage");
    }

    unsigned start = offset;

    unsigned end = offset + size;

    while (offset < end) {
        unsigned entry = offset;
        unsigned consumed = tvb_get_uint8(tvb, entry) + 1;

        offset = parse_nsmequities_orders_optional_field_length(tvb, pinfo, group, offset);
        offset = parse_nsmequities_orders_replace_order_optional_field(tvb, pinfo, group, offset);

        uint32_t replace_order_optional_field = tvb_get_uint8(tvb, entry + 1);

        offset = dissect_nsmequities_orders_replace_order_optional_value(tvb, pinfo, group, offset, replace_order_optional_field);

        offset = entry + consumed;
    }

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Cancel Order Message */
static unsigned
dissect_nsmequities_orders_cancel_order(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;

    offset = parse_nsmequities_orders_user_ref_num(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_quantity(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_appendage_length_v50(tvb, pinfo, tree, offset);

    /* Cancel Order Appendage: spans Appendage Length from here */
    uint32_t cancel_order_appendage = tvb_get_ntohs(tvb, start + 8);

    offset = dissect_nsmequities_orders_cancel_order_appendage(tvb, pinfo, tree, offset, cancel_order_appendage);

    return offset;
}

/* Cancel Order Appendage */
static unsigned
dissect_nsmequities_orders_cancel_order_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (nsmequities_orders_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nsmequities_orders_cancel_order_appendage, &item, "Cancel Order Appendage");
    }

    unsigned start = offset;

    unsigned end = offset + size;

    while (offset < end) {
        unsigned entry = offset;
        unsigned consumed = tvb_get_uint8(tvb, entry) + 1;

        offset = parse_nsmequities_orders_optional_field_length(tvb, pinfo, group, offset);
        offset = parse_nsmequities_orders_cancel_order_optional_field(tvb, pinfo, group, offset);

        uint32_t cancel_order_optional_field = tvb_get_uint8(tvb, entry + 1);

        offset = dissect_nsmequities_orders_cancel_order_optional_value(tvb, pinfo, group, offset, cancel_order_optional_field);

        offset = entry + consumed;
    }

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Modify Order Message */
static unsigned
dissect_nsmequities_orders_modify_order(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;

    offset = parse_nsmequities_orders_user_ref_num(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_side(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_quantity(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_appendage_length_v50(tvb, pinfo, tree, offset);

    /* Modify Order Appendage: spans Appendage Length from here */
    uint32_t modify_order_appendage = tvb_get_ntohs(tvb, start + 9);

    offset = dissect_nsmequities_orders_modify_order_appendage(tvb, pinfo, tree, offset, modify_order_appendage);

    return offset;
}

/* Modify Order Appendage */
static unsigned
dissect_nsmequities_orders_modify_order_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (nsmequities_orders_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nsmequities_orders_modify_order_appendage, &item, "Modify Order Appendage");
    }

    unsigned start = offset;

    unsigned end = offset + size;

    while (offset < end) {
        unsigned entry = offset;
        unsigned consumed = tvb_get_uint8(tvb, entry) + 1;

        offset = parse_nsmequities_orders_optional_field_length(tvb, pinfo, group, offset);
        offset = parse_nsmequities_orders_modify_order_optional_field(tvb, pinfo, group, offset);

        uint32_t modify_order_optional_field = tvb_get_uint8(tvb, entry + 1);

        offset = dissect_nsmequities_orders_modify_order_optional_value(tvb, pinfo, group, offset, modify_order_optional_field);

        offset = entry + consumed;
    }

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Account Query Message */
static unsigned
dissect_nsmequities_orders_account_query(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;

    offset = parse_nsmequities_orders_appendage_length_v50(tvb, pinfo, tree, offset);

    /* Account Query Appendage: spans Appendage Length from here */
    uint32_t account_query_appendage = tvb_get_ntohs(tvb, start);

    offset = dissect_nsmequities_orders_account_query_appendage(tvb, pinfo, tree, offset, account_query_appendage);

    return offset;
}

/* Account Query Appendage */
static unsigned
dissect_nsmequities_orders_account_query_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (nsmequities_orders_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nsmequities_orders_account_query_appendage, &item, "Account Query Appendage");
    }

    unsigned start = offset;

    unsigned end = offset + size;

    while (offset < end) {
        unsigned entry = offset;
        unsigned consumed = tvb_get_uint8(tvb, entry) + 1;

        offset = parse_nsmequities_orders_optional_field_length(tvb, pinfo, group, offset);
        offset = parse_nsmequities_orders_account_query_optional_field(tvb, pinfo, group, offset);

        uint32_t account_query_optional_field = tvb_get_uint8(tvb, entry + 1);

        offset = dissect_nsmequities_orders_account_query_optional_value(tvb, pinfo, group, offset, account_query_optional_field);

        offset = entry + consumed;
    }

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Mass Cancel Request Message */
static unsigned
dissect_nsmequities_orders_mass_cancel_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;

    offset = parse_nsmequities_orders_user_ref_num(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_firm(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_symbol(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_appendage_length(tvb, pinfo, tree, offset);

    /* Mass Cancel Request Appendage: spans Appendage Length from here */
    uint32_t mass_cancel_request_appendage = tvb_get_ntohs(tvb, start + 16);

    offset = dissect_nsmequities_orders_mass_cancel_request_appendage(tvb, pinfo, tree, offset, mass_cancel_request_appendage);

    return offset;
}

/* Mass Cancel Request Appendage */
static unsigned
dissect_nsmequities_orders_mass_cancel_request_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (nsmequities_orders_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nsmequities_orders_mass_cancel_request_appendage, &item, "Mass Cancel Request Appendage");
    }

    unsigned start = offset;

    unsigned end = offset + size;

    while (offset < end) {
        unsigned entry = offset;
        unsigned consumed = tvb_get_uint8(tvb, entry) + 1;

        offset = parse_nsmequities_orders_optional_field_length(tvb, pinfo, group, offset);
        offset = parse_nsmequities_orders_mass_cancel_request_optional_field(tvb, pinfo, group, offset);

        uint32_t mass_cancel_request_optional_field = tvb_get_uint8(tvb, entry + 1);

        offset = dissect_nsmequities_orders_mass_cancel_request_optional_value(tvb, pinfo, group, offset, mass_cancel_request_optional_field);

        offset = entry + consumed;
    }

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Disable Order Entry Request Message */
static unsigned
dissect_nsmequities_orders_disable_order_entry_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;

    offset = parse_nsmequities_orders_user_ref_num(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_firm(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_appendage_length(tvb, pinfo, tree, offset);

    /* Disable Order Entry Request Appendage: spans Appendage Length from here */
    uint32_t disable_order_entry_request_appendage = tvb_get_ntohs(tvb, start + 8);

    offset = dissect_nsmequities_orders_disable_order_entry_request_appendage(tvb, pinfo, tree, offset, disable_order_entry_request_appendage);

    return offset;
}

/* Disable Order Entry Request Appendage */
static unsigned
dissect_nsmequities_orders_disable_order_entry_request_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (nsmequities_orders_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nsmequities_orders_disable_order_entry_request_appendage, &item, "Disable Order Entry Request Appendage");
    }

    unsigned start = offset;

    unsigned end = offset + size;

    while (offset < end) {
        unsigned entry = offset;
        unsigned consumed = tvb_get_uint8(tvb, entry) + 1;

        offset = parse_nsmequities_orders_optional_field_length(tvb, pinfo, group, offset);
        offset = parse_nsmequities_orders_disable_order_entry_request_optional_field(tvb, pinfo, group, offset);

        uint32_t disable_order_entry_request_optional_field = tvb_get_uint8(tvb, entry + 1);

        offset = dissect_nsmequities_orders_disable_order_entry_request_optional_value(tvb, pinfo, group, offset, disable_order_entry_request_optional_field);

        offset = entry + consumed;
    }

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Enable Order Entry Request Message */
static unsigned
dissect_nsmequities_orders_enable_order_entry_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;

    offset = parse_nsmequities_orders_user_ref_num(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_firm(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_appendage_length(tvb, pinfo, tree, offset);

    /* Enable Order Entry Request Appendage: spans Appendage Length from here */
    uint32_t enable_order_entry_request_appendage = tvb_get_ntohs(tvb, start + 8);

    offset = dissect_nsmequities_orders_enable_order_entry_request_appendage(tvb, pinfo, tree, offset, enable_order_entry_request_appendage);

    return offset;
}

/* Enable Order Entry Request Appendage */
static unsigned
dissect_nsmequities_orders_enable_order_entry_request_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (nsmequities_orders_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nsmequities_orders_enable_order_entry_request_appendage, &item, "Enable Order Entry Request Appendage");
    }

    unsigned start = offset;

    unsigned end = offset + size;

    while (offset < end) {
        unsigned entry = offset;
        unsigned consumed = tvb_get_uint8(tvb, entry) + 1;

        offset = parse_nsmequities_orders_optional_field_length(tvb, pinfo, group, offset);
        offset = parse_nsmequities_orders_enable_order_entry_request_optional_field(tvb, pinfo, group, offset);

        uint32_t enable_order_entry_request_optional_field = tvb_get_uint8(tvb, entry + 1);

        offset = dissect_nsmequities_orders_enable_order_entry_request_optional_value(tvb, pinfo, group, offset, enable_order_entry_request_optional_field);

        offset = entry + consumed;
    }

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Server Packet Header */
static unsigned
dissect_nsmequities_orders_server_packet_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (nsmequities_orders_show_headers) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nsmequities_orders_server_packet_header, &item, "Server Packet Header");
    }

    unsigned start = offset;

    offset = parse_nsmequities_orders_packet_length(tvb, pinfo, group, offset);
    offset = parse_nsmequities_orders_server_packet_type(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Login Accepted Packet */
static unsigned
dissect_nsmequities_orders_login_accepted_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_orders_accepted_session(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_accepted_sequence_number(tvb, pinfo, tree, offset);

    return offset;
}

/* Login Rejected Packet */
static unsigned
dissect_nsmequities_orders_login_rejected_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_orders_reject_reason_code(tvb, pinfo, tree, offset);

    return offset;
}

/* Sequenced Data Packet */
static unsigned
dissect_nsmequities_orders_sequenced_data_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;

    offset = parse_nsmequities_orders_sequenced_message_type(tvb, pinfo, tree, offset);

    uint32_t sequenced_message_type = tvb_get_uint8(tvb, start);

    offset = dissect_nsmequities_orders_sequenced_message(tvb, pinfo, tree, offset, sequenced_message_type);

    return offset;
}

/* System Event Message */
static unsigned
dissect_nsmequities_orders_system_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_orders_timestamp(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_event_code(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Accepted Message */
static unsigned
dissect_nsmequities_orders_order_accepted(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;

    offset = parse_nsmequities_orders_timestamp(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_user_ref_num(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_side(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_quantity(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_symbol(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_price(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_time_in_force(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_display(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_order_reference_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_capacity(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_inter_market_sweep_eligibility(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_cross_type(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_order_state(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_clordid(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_appendage_length(tvb, pinfo, tree, offset);

    /* Order Accepted Appendage: spans Appendage Length from here */
    uint32_t order_accepted_appendage = tvb_get_ntohs(tvb, start + 61);

    offset = dissect_nsmequities_orders_order_accepted_appendage(tvb, pinfo, tree, offset, order_accepted_appendage);

    return offset;
}

/* Order Accepted Appendage */
static unsigned
dissect_nsmequities_orders_order_accepted_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (nsmequities_orders_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nsmequities_orders_order_accepted_appendage, &item, "Order Accepted Appendage");
    }

    unsigned start = offset;

    unsigned end = offset + size;

    while (offset < end) {
        unsigned entry = offset;
        unsigned consumed = tvb_get_uint8(tvb, entry) + 1;

        offset = parse_nsmequities_orders_optional_field_length(tvb, pinfo, group, offset);
        offset = parse_nsmequities_orders_order_accepted_optional_field(tvb, pinfo, group, offset);

        uint32_t order_accepted_optional_field = tvb_get_uint8(tvb, entry + 1);

        offset = dissect_nsmequities_orders_order_accepted_optional_value(tvb, pinfo, group, offset, order_accepted_optional_field);

        offset = entry + consumed;
    }

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Replaced Message */
static unsigned
dissect_nsmequities_orders_replaced(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;

    offset = parse_nsmequities_orders_timestamp(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_orig_user_ref_num(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_user_ref_num(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_side(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_quantity(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_symbol(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_price(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_time_in_force(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_display(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_order_reference_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_capacity(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_inter_market_sweep_eligibility(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_cross_type(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_order_state(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_clordid(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_appendage_length(tvb, pinfo, tree, offset);

    /* Replaced Message Appendage: spans Appendage Length from here */
    uint32_t replaced_message_appendage = tvb_get_ntohs(tvb, start + 65);

    offset = dissect_nsmequities_orders_replaced_message_appendage(tvb, pinfo, tree, offset, replaced_message_appendage);

    return offset;
}

/* Replaced Message Appendage */
static unsigned
dissect_nsmequities_orders_replaced_message_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (nsmequities_orders_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nsmequities_orders_replaced_message_appendage, &item, "Replaced Message Appendage");
    }

    unsigned start = offset;

    unsigned end = offset + size;

    while (offset < end) {
        unsigned entry = offset;
        unsigned consumed = tvb_get_uint8(tvb, entry) + 1;

        offset = parse_nsmequities_orders_optional_field_length(tvb, pinfo, group, offset);
        offset = parse_nsmequities_orders_replaced_message_optional_field(tvb, pinfo, group, offset);

        uint32_t replaced_message_optional_field = tvb_get_uint8(tvb, entry + 1);

        offset = dissect_nsmequities_orders_replaced_message_optional_value(tvb, pinfo, group, offset, replaced_message_optional_field);

        offset = entry + consumed;
    }

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Canceled Message */
static unsigned
dissect_nsmequities_orders_canceled(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;

    offset = parse_nsmequities_orders_timestamp(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_user_ref_num(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_quantity(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_cancel_order_reason(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_appendage_length_v50(tvb, pinfo, tree, offset);

    /* Canceled Message Appendage: spans Appendage Length from here */
    uint32_t canceled_message_appendage = tvb_get_ntohs(tvb, start + 17);

    offset = dissect_nsmequities_orders_canceled_message_appendage(tvb, pinfo, tree, offset, canceled_message_appendage);

    return offset;
}

/* Canceled Message Appendage */
static unsigned
dissect_nsmequities_orders_canceled_message_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (nsmequities_orders_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nsmequities_orders_canceled_message_appendage, &item, "Canceled Message Appendage");
    }

    unsigned start = offset;

    unsigned end = offset + size;

    while (offset < end) {
        unsigned entry = offset;
        unsigned consumed = tvb_get_uint8(tvb, entry) + 1;

        offset = parse_nsmequities_orders_optional_field_length(tvb, pinfo, group, offset);
        offset = parse_nsmequities_orders_canceled_message_optional_field(tvb, pinfo, group, offset);

        uint32_t canceled_message_optional_field = tvb_get_uint8(tvb, entry + 1);

        offset = dissect_nsmequities_orders_canceled_message_optional_value(tvb, pinfo, group, offset, canceled_message_optional_field);

        offset = entry + consumed;
    }

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Aiq Canceled Message */
static unsigned
dissect_nsmequities_orders_aiq_canceled(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;

    offset = parse_nsmequities_orders_timestamp(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_user_ref_num(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_decrement_shares(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_order_cancel_reason(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_quantity_prevented_from_trading(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_execution_price(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_liquidity_flag(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_aiq_strategy(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_appendage_length_v50(tvb, pinfo, tree, offset);

    /* Aiq Canceled Appendage: spans Appendage Length from here */
    uint32_t aiq_canceled_appendage = tvb_get_ntohs(tvb, start + 31);

    offset = dissect_nsmequities_orders_aiq_canceled_appendage(tvb, pinfo, tree, offset, aiq_canceled_appendage);

    return offset;
}

/* Aiq Canceled Appendage */
static unsigned
dissect_nsmequities_orders_aiq_canceled_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (nsmequities_orders_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nsmequities_orders_aiq_canceled_appendage, &item, "Aiq Canceled Appendage");
    }

    unsigned start = offset;

    unsigned end = offset + size;

    while (offset < end) {
        unsigned entry = offset;
        unsigned consumed = tvb_get_uint8(tvb, entry) + 1;

        offset = parse_nsmequities_orders_optional_field_length(tvb, pinfo, group, offset);
        offset = parse_nsmequities_orders_aiq_canceled_optional_field(tvb, pinfo, group, offset);

        uint32_t aiq_canceled_optional_field = tvb_get_uint8(tvb, entry + 1);

        offset = dissect_nsmequities_orders_aiq_canceled_optional_value(tvb, pinfo, group, offset, aiq_canceled_optional_field);

        offset = entry + consumed;
    }

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Order Executed Message */
static unsigned
dissect_nsmequities_orders_order_executed(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;

    offset = parse_nsmequities_orders_timestamp(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_user_ref_num(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_quantity(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_price(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_liquidity_flag(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_match_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_appendage_length(tvb, pinfo, tree, offset);

    /* Order Executed Appendage: spans Appendage Length from here */
    uint32_t order_executed_appendage = tvb_get_ntohs(tvb, start + 33);

    offset = dissect_nsmequities_orders_order_executed_appendage(tvb, pinfo, tree, offset, order_executed_appendage);

    return offset;
}

/* Order Executed Appendage */
static unsigned
dissect_nsmequities_orders_order_executed_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (nsmequities_orders_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nsmequities_orders_order_executed_appendage, &item, "Order Executed Appendage");
    }

    unsigned start = offset;

    unsigned end = offset + size;

    while (offset < end) {
        unsigned entry = offset;
        unsigned consumed = tvb_get_uint8(tvb, entry) + 1;

        offset = parse_nsmequities_orders_optional_field_length(tvb, pinfo, group, offset);
        offset = parse_nsmequities_orders_order_executed_optional_field(tvb, pinfo, group, offset);

        uint32_t order_executed_optional_field = tvb_get_uint8(tvb, entry + 1);

        offset = dissect_nsmequities_orders_order_executed_optional_value(tvb, pinfo, group, offset, order_executed_optional_field);

        offset = entry + consumed;
    }

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Broken Trade Message */
static unsigned
dissect_nsmequities_orders_broken_trade(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;

    offset = parse_nsmequities_orders_timestamp(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_user_ref_num(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_match_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_broken_trade_reason(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_clordid(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_appendage_length_v50(tvb, pinfo, tree, offset);

    /* Broken Trade Appendage: spans Appendage Length from here */
    uint32_t broken_trade_appendage = tvb_get_ntohs(tvb, start + 35);

    offset = dissect_nsmequities_orders_broken_trade_appendage(tvb, pinfo, tree, offset, broken_trade_appendage);

    return offset;
}

/* Broken Trade Appendage */
static unsigned
dissect_nsmequities_orders_broken_trade_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (nsmequities_orders_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nsmequities_orders_broken_trade_appendage, &item, "Broken Trade Appendage");
    }

    unsigned start = offset;

    unsigned end = offset + size;

    while (offset < end) {
        unsigned entry = offset;
        unsigned consumed = tvb_get_uint8(tvb, entry) + 1;

        offset = parse_nsmequities_orders_optional_field_length(tvb, pinfo, group, offset);
        offset = parse_nsmequities_orders_broken_trade_optional_field(tvb, pinfo, group, offset);

        uint32_t broken_trade_optional_field = tvb_get_uint8(tvb, entry + 1);

        offset = dissect_nsmequities_orders_broken_trade_optional_value(tvb, pinfo, group, offset, broken_trade_optional_field);

        offset = entry + consumed;
    }

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Rejected Order Message */
static unsigned
dissect_nsmequities_orders_rejected_order(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;

    offset = parse_nsmequities_orders_timestamp(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_user_ref_num(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_rejected_order_reason(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_clordid(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_appendage_length_v50(tvb, pinfo, tree, offset);

    /* Rejected Order Appendage: spans Appendage Length from here */
    uint32_t rejected_order_appendage = tvb_get_ntohs(tvb, start + 28);

    offset = dissect_nsmequities_orders_rejected_order_appendage(tvb, pinfo, tree, offset, rejected_order_appendage);

    return offset;
}

/* Rejected Order Appendage */
static unsigned
dissect_nsmequities_orders_rejected_order_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (nsmequities_orders_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nsmequities_orders_rejected_order_appendage, &item, "Rejected Order Appendage");
    }

    unsigned start = offset;

    unsigned end = offset + size;

    while (offset < end) {
        unsigned entry = offset;
        unsigned consumed = tvb_get_uint8(tvb, entry) + 1;

        offset = parse_nsmequities_orders_optional_field_length(tvb, pinfo, group, offset);
        offset = parse_nsmequities_orders_rejected_order_optional_field(tvb, pinfo, group, offset);

        uint32_t rejected_order_optional_field = tvb_get_uint8(tvb, entry + 1);

        offset = dissect_nsmequities_orders_rejected_order_optional_value(tvb, pinfo, group, offset, rejected_order_optional_field);

        offset = entry + consumed;
    }

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Cancel Pending Message */
static unsigned
dissect_nsmequities_orders_cancel_pending(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;

    offset = parse_nsmequities_orders_timestamp(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_user_ref_num(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_appendage_length_v50(tvb, pinfo, tree, offset);

    /* Cancel Pending Appendage: spans Appendage Length from here */
    uint32_t cancel_pending_appendage = tvb_get_ntohs(tvb, start + 12);

    offset = dissect_nsmequities_orders_cancel_pending_appendage(tvb, pinfo, tree, offset, cancel_pending_appendage);

    return offset;
}

/* Cancel Pending Appendage */
static unsigned
dissect_nsmequities_orders_cancel_pending_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (nsmequities_orders_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nsmequities_orders_cancel_pending_appendage, &item, "Cancel Pending Appendage");
    }

    unsigned start = offset;

    unsigned end = offset + size;

    while (offset < end) {
        unsigned entry = offset;
        unsigned consumed = tvb_get_uint8(tvb, entry) + 1;

        offset = parse_nsmequities_orders_optional_field_length(tvb, pinfo, group, offset);
        offset = parse_nsmequities_orders_cancel_pending_optional_field(tvb, pinfo, group, offset);

        uint32_t cancel_pending_optional_field = tvb_get_uint8(tvb, entry + 1);

        offset = dissect_nsmequities_orders_cancel_pending_optional_value(tvb, pinfo, group, offset, cancel_pending_optional_field);

        offset = entry + consumed;
    }

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Cancel Reject Message */
static unsigned
dissect_nsmequities_orders_cancel_reject(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;

    offset = parse_nsmequities_orders_timestamp(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_user_ref_num(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_appendage_length_v50(tvb, pinfo, tree, offset);

    /* Cancel Reject Appendage: spans Appendage Length from here */
    uint32_t cancel_reject_appendage = tvb_get_ntohs(tvb, start + 12);

    offset = dissect_nsmequities_orders_cancel_reject_appendage(tvb, pinfo, tree, offset, cancel_reject_appendage);

    return offset;
}

/* Cancel Reject Appendage */
static unsigned
dissect_nsmequities_orders_cancel_reject_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (nsmequities_orders_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nsmequities_orders_cancel_reject_appendage, &item, "Cancel Reject Appendage");
    }

    unsigned start = offset;

    unsigned end = offset + size;

    while (offset < end) {
        unsigned entry = offset;
        unsigned consumed = tvb_get_uint8(tvb, entry) + 1;

        offset = parse_nsmequities_orders_optional_field_length(tvb, pinfo, group, offset);
        offset = parse_nsmequities_orders_cancel_reject_optional_field(tvb, pinfo, group, offset);

        uint32_t cancel_reject_optional_field = tvb_get_uint8(tvb, entry + 1);

        offset = dissect_nsmequities_orders_cancel_reject_optional_value(tvb, pinfo, group, offset, cancel_reject_optional_field);

        offset = entry + consumed;
    }

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Order Priority Update Message */
static unsigned
dissect_nsmequities_orders_order_priority_update(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;

    offset = parse_nsmequities_orders_timestamp(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_user_ref_num(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_price(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_display(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_order_reference_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_appendage_length_v50(tvb, pinfo, tree, offset);

    /* Order Priority Update Appendage: spans Appendage Length from here */
    uint32_t order_priority_update_appendage = tvb_get_ntohs(tvb, start + 29);

    offset = dissect_nsmequities_orders_order_priority_update_appendage(tvb, pinfo, tree, offset, order_priority_update_appendage);

    return offset;
}

/* Order Priority Update Appendage */
static unsigned
dissect_nsmequities_orders_order_priority_update_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (nsmequities_orders_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nsmequities_orders_order_priority_update_appendage, &item, "Order Priority Update Appendage");
    }

    unsigned start = offset;

    unsigned end = offset + size;

    while (offset < end) {
        unsigned entry = offset;
        unsigned consumed = tvb_get_uint8(tvb, entry) + 1;

        offset = parse_nsmequities_orders_optional_field_length(tvb, pinfo, group, offset);
        offset = parse_nsmequities_orders_order_priority_update_optional_field(tvb, pinfo, group, offset);

        uint32_t order_priority_update_optional_field = tvb_get_uint8(tvb, entry + 1);

        offset = dissect_nsmequities_orders_order_priority_update_optional_value(tvb, pinfo, group, offset, order_priority_update_optional_field);

        offset = entry + consumed;
    }

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Order Modified Message */
static unsigned
dissect_nsmequities_orders_order_modified(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;

    offset = parse_nsmequities_orders_timestamp(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_user_ref_num(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_side(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_quantity(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_appendage_length_v50(tvb, pinfo, tree, offset);

    /* Order Modified Appendage: spans Appendage Length from here */
    uint32_t order_modified_appendage = tvb_get_ntohs(tvb, start + 17);

    offset = dissect_nsmequities_orders_order_modified_appendage(tvb, pinfo, tree, offset, order_modified_appendage);

    return offset;
}

/* Order Modified Appendage */
static unsigned
dissect_nsmequities_orders_order_modified_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (nsmequities_orders_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nsmequities_orders_order_modified_appendage, &item, "Order Modified Appendage");
    }

    unsigned start = offset;

    unsigned end = offset + size;

    while (offset < end) {
        unsigned entry = offset;
        unsigned consumed = tvb_get_uint8(tvb, entry) + 1;

        offset = parse_nsmequities_orders_optional_field_length(tvb, pinfo, group, offset);
        offset = parse_nsmequities_orders_order_modified_optional_field(tvb, pinfo, group, offset);

        uint32_t order_modified_optional_field = tvb_get_uint8(tvb, entry + 1);

        offset = dissect_nsmequities_orders_order_modified_optional_value(tvb, pinfo, group, offset, order_modified_optional_field);

        offset = entry + consumed;
    }

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Order Restated Message */
static unsigned
dissect_nsmequities_orders_order_restated(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;

    offset = parse_nsmequities_orders_timestamp(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_user_ref_num(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_order_restated_reason(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_appendage_length(tvb, pinfo, tree, offset);

    /* Order Restated Appendage: spans Appendage Length from here */
    uint32_t order_restated_appendage = tvb_get_ntohs(tvb, start + 13);

    offset = dissect_nsmequities_orders_order_restated_appendage(tvb, pinfo, tree, offset, order_restated_appendage);

    return offset;
}

/* Order Restated Appendage */
static unsigned
dissect_nsmequities_orders_order_restated_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (nsmequities_orders_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nsmequities_orders_order_restated_appendage, &item, "Order Restated Appendage");
    }

    unsigned start = offset;

    unsigned end = offset + size;

    while (offset < end) {
        unsigned entry = offset;
        unsigned consumed = tvb_get_uint8(tvb, entry) + 1;

        offset = parse_nsmequities_orders_optional_field_length(tvb, pinfo, group, offset);
        offset = parse_nsmequities_orders_order_restated_optional_field(tvb, pinfo, group, offset);

        uint32_t order_restated_optional_field = tvb_get_uint8(tvb, entry + 1);

        offset = dissect_nsmequities_orders_order_restated_optional_value(tvb, pinfo, group, offset, order_restated_optional_field);

        offset = entry + consumed;
    }

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Account Query Response Message */
static unsigned
dissect_nsmequities_orders_account_query_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;

    offset = parse_nsmequities_orders_timestamp(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_next_user_ref_num(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_appendage_length_v50(tvb, pinfo, tree, offset);

    /* Account Query Response Appendage: spans Appendage Length from here */
    uint32_t account_query_response_appendage = tvb_get_ntohs(tvb, start + 12);

    offset = dissect_nsmequities_orders_account_query_response_appendage(tvb, pinfo, tree, offset, account_query_response_appendage);

    return offset;
}

/* Account Query Response Appendage */
static unsigned
dissect_nsmequities_orders_account_query_response_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (nsmequities_orders_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nsmequities_orders_account_query_response_appendage, &item, "Account Query Response Appendage");
    }

    unsigned start = offset;

    unsigned end = offset + size;

    while (offset < end) {
        unsigned entry = offset;
        unsigned consumed = tvb_get_uint8(tvb, entry) + 1;

        offset = parse_nsmequities_orders_optional_field_length(tvb, pinfo, group, offset);
        offset = parse_nsmequities_orders_account_query_response_optional_field(tvb, pinfo, group, offset);

        uint32_t account_query_response_optional_field = tvb_get_uint8(tvb, entry + 1);

        offset = dissect_nsmequities_orders_account_query_response_optional_value(tvb, pinfo, group, offset, account_query_response_optional_field);

        offset = entry + consumed;
    }

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Mass Cancel Response Message */
static unsigned
dissect_nsmequities_orders_mass_cancel_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;

    offset = parse_nsmequities_orders_timestamp(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_user_ref_num(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_firm(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_symbol(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_appendage_length(tvb, pinfo, tree, offset);

    /* Mass Cancel Response Appendage: spans Appendage Length from here */
    uint32_t mass_cancel_response_appendage = tvb_get_ntohs(tvb, start + 24);

    offset = dissect_nsmequities_orders_mass_cancel_response_appendage(tvb, pinfo, tree, offset, mass_cancel_response_appendage);

    return offset;
}

/* Mass Cancel Response Appendage */
static unsigned
dissect_nsmequities_orders_mass_cancel_response_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (nsmequities_orders_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nsmequities_orders_mass_cancel_response_appendage, &item, "Mass Cancel Response Appendage");
    }

    unsigned start = offset;

    unsigned end = offset + size;

    while (offset < end) {
        unsigned entry = offset;
        unsigned consumed = tvb_get_uint8(tvb, entry) + 1;

        offset = parse_nsmequities_orders_optional_field_length(tvb, pinfo, group, offset);
        offset = parse_nsmequities_orders_mass_cancel_response_optional_field(tvb, pinfo, group, offset);

        uint32_t mass_cancel_response_optional_field = tvb_get_uint8(tvb, entry + 1);

        offset = dissect_nsmequities_orders_mass_cancel_response_optional_value(tvb, pinfo, group, offset, mass_cancel_response_optional_field);

        offset = entry + consumed;
    }

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Disable Order Entry Response Message */
static unsigned
dissect_nsmequities_orders_disable_order_entry_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;

    offset = parse_nsmequities_orders_timestamp(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_user_ref_num(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_firm(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_appendage_length(tvb, pinfo, tree, offset);

    /* Disable Order Entry Response Appendage: spans Appendage Length from here */
    uint32_t disable_order_entry_response_appendage = tvb_get_ntohs(tvb, start + 16);

    offset = dissect_nsmequities_orders_disable_order_entry_response_appendage(tvb, pinfo, tree, offset, disable_order_entry_response_appendage);

    return offset;
}

/* Disable Order Entry Response Appendage */
static unsigned
dissect_nsmequities_orders_disable_order_entry_response_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (nsmequities_orders_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nsmequities_orders_disable_order_entry_response_appendage, &item, "Disable Order Entry Response Appendage");
    }

    unsigned start = offset;

    unsigned end = offset + size;

    while (offset < end) {
        unsigned entry = offset;
        unsigned consumed = tvb_get_uint8(tvb, entry) + 1;

        offset = parse_nsmequities_orders_optional_field_length(tvb, pinfo, group, offset);
        offset = parse_nsmequities_orders_disable_order_entry_response_optional_field(tvb, pinfo, group, offset);

        uint32_t disable_order_entry_response_optional_field = tvb_get_uint8(tvb, entry + 1);

        offset = dissect_nsmequities_orders_disable_order_entry_response_optional_value(tvb, pinfo, group, offset, disable_order_entry_response_optional_field);

        offset = entry + consumed;
    }

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Enable Order Entry Response Message */
static unsigned
dissect_nsmequities_orders_enable_order_entry_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;

    offset = parse_nsmequities_orders_timestamp(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_user_ref_num(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_firm(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_appendage_length(tvb, pinfo, tree, offset);

    /* Enable Order Entry Response Appendage: spans Appendage Length from here */
    uint32_t enable_order_entry_response_appendage = tvb_get_ntohs(tvb, start + 16);

    offset = dissect_nsmequities_orders_enable_order_entry_response_appendage(tvb, pinfo, tree, offset, enable_order_entry_response_appendage);

    return offset;
}

/* Enable Order Entry Response Appendage */
static unsigned
dissect_nsmequities_orders_enable_order_entry_response_appendage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, int size)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (nsmequities_orders_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_nsmequities_orders_enable_order_entry_response_appendage, &item, "Enable Order Entry Response Appendage");
    }

    unsigned start = offset;

    unsigned end = offset + size;

    while (offset < end) {
        unsigned entry = offset;
        unsigned consumed = tvb_get_uint8(tvb, entry) + 1;

        offset = parse_nsmequities_orders_optional_field_length(tvb, pinfo, group, offset);
        offset = parse_nsmequities_orders_enable_order_entry_response_optional_field(tvb, pinfo, group, offset);

        uint32_t enable_order_entry_response_optional_field = tvb_get_uint8(tvb, entry + 1);

        offset = dissect_nsmequities_orders_enable_order_entry_response_optional_value(tvb, pinfo, group, offset, enable_order_entry_response_optional_field);

        offset = entry + consumed;
    }

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Unsequenced Data Packet */
static unsigned
dissect_nsmequities_orders_unsequenced_data_packet_v422018(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;

    offset = parse_nsmequities_orders_unsequenced_message_type(tvb, pinfo, tree, offset);

    uint32_t unsequenced_message_type = tvb_get_uint8(tvb, start);

    offset = dissect_nsmequities_orders_unsequenced_message_v422018(tvb, pinfo, tree, offset, unsequenced_message_type);

    return offset;
}

/* Enter Order Message V422018 */
static unsigned
dissect_nsmequities_orders_enter_order_v422018(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_orders_order_token(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_buy_sell_indicator(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_shares(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_stock(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_price_v422018(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_time_in_force_v422018(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_firm(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_display(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_capacity(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_intermarket_sweep_eligibility(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_minimum_quantity(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_cross_type(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_customer_type_v422018(tvb, pinfo, tree, offset);

    return offset;
}

/* Replace Order Message V422018 */
static unsigned
dissect_nsmequities_orders_replace_order_v422018(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_orders_existing_order_token(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_replacement_order_token(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_shares(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_price_v422018(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_time_in_force_v422018(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_display(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_intermarket_sweep_eligibility(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_minimum_quantity(tvb, pinfo, tree, offset);

    return offset;
}

/* Cancel Order Message V422018 */
static unsigned
dissect_nsmequities_orders_cancel_order_v422018(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_orders_order_token(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_shares(tvb, pinfo, tree, offset);

    return offset;
}

/* Modify Order Message V422018 */
static unsigned
dissect_nsmequities_orders_modify_order_v422018(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_orders_order_token(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_buy_sell_indicator(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_shares(tvb, pinfo, tree, offset);

    return offset;
}

/* Trade Now Message */
static unsigned
dissect_nsmequities_orders_trade_now(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_orders_order_token(tvb, pinfo, tree, offset);

    return offset;
}

/* Sequenced Data Packet */
static unsigned
dissect_nsmequities_orders_sequenced_data_packet_v422018(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;

    offset = parse_nsmequities_orders_sequenced_message_type(tvb, pinfo, tree, offset);

    uint32_t sequenced_message_type = tvb_get_uint8(tvb, start);

    offset = dissect_nsmequities_orders_sequenced_message_v422018(tvb, pinfo, tree, offset, sequenced_message_type);

    return offset;
}

/* System Event Message */
static unsigned
dissect_nsmequities_orders_system_event_v422018(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_orders_timestamp_v422018(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_event_code(tvb, pinfo, tree, offset);

    return offset;
}

/* Accepted Message */
static unsigned
dissect_nsmequities_orders_accepted(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_orders_timestamp_v422018(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_order_token(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_buy_sell_indicator(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_shares(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_stock(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_price_v422018(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_time_in_force_v422018(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_firm(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_display(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_order_reference_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_capacity(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_intermarket_sweep_eligibility(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_minimum_quantity(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_cross_type(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_order_state(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_bbo_weight_indicator(tvb, pinfo, tree, offset);

    return offset;
}

/* Replaced Message V422018 */
static unsigned
dissect_nsmequities_orders_replaced_v422018(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_orders_timestamp_v422018(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_replacement_order_token(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_buy_sell_indicator(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_shares(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_stock(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_price_v422018(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_time_in_force_v422018(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_firm(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_display(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_order_reference_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_capacity(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_intermarket_sweep_eligibility(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_minimum_quantity(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_cross_type(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_order_state(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_previous_order_token(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_bbo_weight_indicator(tvb, pinfo, tree, offset);

    return offset;
}

/* Canceled Message V422018 */
static unsigned
dissect_nsmequities_orders_canceled_v422018(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_orders_timestamp_v422018(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_order_token(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_decrement_shares(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_cancel_order_reason(tvb, pinfo, tree, offset);

    return offset;
}

/* Aiq Cancelled Message */
static unsigned
dissect_nsmequities_orders_aiq_cancelled(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_orders_timestamp_v422018(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_order_token(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_decrement_shares(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_cancel_order_reason(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_quantity_prevented_from_trading(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_execution_price_v422018(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_liquidity_flag(tvb, pinfo, tree, offset);

    return offset;
}

/* Executed Message */
static unsigned
dissect_nsmequities_orders_executed(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_orders_timestamp_v422018(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_order_token(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_executed_shares(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_execution_price_v422018(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_liquidity_flag(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_match_number(tvb, pinfo, tree, offset);

    return offset;
}

/* Broken Trade Message V422018 */
static unsigned
dissect_nsmequities_orders_broken_trade_v422018(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_orders_timestamp_v422018(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_order_token(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_match_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_broken_trade_reason(tvb, pinfo, tree, offset);

    return offset;
}

/* Executed With Reference Price Message */
static unsigned
dissect_nsmequities_orders_executed_with_reference_price(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_orders_timestamp_v422018(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_order_token(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_executed_shares(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_execution_price_v422018(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_liquidity_flag(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_match_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_reference_price(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_reference_price_type(tvb, pinfo, tree, offset);

    return offset;
}

/* Trade Correction Message */
static unsigned
dissect_nsmequities_orders_trade_correction(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_orders_timestamp_v422018(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_order_token(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_executed_shares(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_execution_price_v422018(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_liquidity_flag(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_match_number(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_reason(tvb, pinfo, tree, offset);

    return offset;
}

/* Rejected Order Message V422018 */
static unsigned
dissect_nsmequities_orders_rejected_order_v422018(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_orders_timestamp_v422018(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_order_token(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_rejected_order_reason_v422018(tvb, pinfo, tree, offset);

    return offset;
}

/* Cancel Pending Message V422018 */
static unsigned
dissect_nsmequities_orders_cancel_pending_v422018(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_orders_timestamp_v422018(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_order_token(tvb, pinfo, tree, offset);

    return offset;
}

/* Cancel Reject Message V422018 */
static unsigned
dissect_nsmequities_orders_cancel_reject_v422018(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_orders_timestamp_v422018(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_order_token(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Priority Update Message V422018 */
static unsigned
dissect_nsmequities_orders_order_priority_update_v422018(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_orders_timestamp_v422018(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_order_token(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_price_v422018(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_display(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_order_reference_number(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Modified Message V422018 */
static unsigned
dissect_nsmequities_orders_order_modified_v422018(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_orders_timestamp_v422018(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_order_token(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_buy_sell_indicator(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_shares(tvb, pinfo, tree, offset);

    return offset;
}

/* Sequenced Trade Now Message */
static unsigned
dissect_nsmequities_orders_sequenced_trade_now(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_nsmequities_orders_timestamp_v422018(tvb, pinfo, tree, offset);
    offset = parse_nsmequities_orders_order_token(tvb, pinfo, tree, offset);

    return offset;
}

/*
 * NsmEquities Orders Parse Trees, a dispatch per distinct branch definition
 */

static const value_string nsmequities_orders_client_packet_messages[] = {
    { NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_DEBUG_PACKET, "Debug Packet" },
    { NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_LOGIN_REQUEST_PACKET, "Login Request Packet" },
    { NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_UNSEQUENCED_DATA_PACKET, "Unsequenced Data Packet" },
    { NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_CLIENT_HEARTBEAT_PACKET, "Client Heartbeat" },
    { NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_LOGOUT_REQUEST_PACKET, "Logout Request" },
    { 0, NULL }
};

/* Client Payload: dispatch on client_packet_type */
static unsigned
dissect_nsmequities_orders_client_packet_client_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t client_packet_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, client_packet_type, nsmequities_orders_client_packet_messages, "Unknown (%u)"));

    switch (client_packet_type) {
    case NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_DEBUG_PACKET:
        return dissect_nsmequities_orders_debug_packet(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_LOGIN_REQUEST_PACKET:
        return dissect_nsmequities_orders_login_request_packet(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_UNSEQUENCED_DATA_PACKET:
        return dissect_nsmequities_orders_unsequenced_data_packet(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_CLIENT_HEARTBEAT_PACKET: /* Client Heartbeat */
        return offset;
    case NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_LOGOUT_REQUEST_PACKET: /* Logout Request */
        return offset;
    }

    return offset;
}

static const value_string nsmequities_orders_client_packet_messages_v422018[] = {
    { NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_DEBUG_PACKET, "Debug Packet" },
    { NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_LOGIN_REQUEST_PACKET, "Login Request Packet" },
    { NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_UNSEQUENCED_DATA_PACKET, "Unsequenced Data Packet" },
    { NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_CLIENT_HEARTBEAT_PACKET, "Client Heartbeat" },
    { NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_LOGOUT_REQUEST_PACKET, "Logout Request" },
    { 0, NULL }
};

/* Client Payload: dispatch on client_packet_type */
static unsigned
dissect_nsmequities_orders_client_packet_client_payload_v422018(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t client_packet_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, client_packet_type, nsmequities_orders_client_packet_messages_v422018, "Unknown (%u)"));

    switch (client_packet_type) {
    case NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_DEBUG_PACKET:
        return dissect_nsmequities_orders_debug_packet(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_LOGIN_REQUEST_PACKET:
        return dissect_nsmequities_orders_login_request_packet(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_UNSEQUENCED_DATA_PACKET:
        return dissect_nsmequities_orders_unsequenced_data_packet_v422018(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_CLIENT_HEARTBEAT_PACKET: /* Client Heartbeat */
        return offset;
    case NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_LOGOUT_REQUEST_PACKET: /* Logout Request */
        return offset;
    }

    return offset;
}

static const value_string nsmequities_orders_unsequenced_message_messages[] = {
    { NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_ENTER_ORDER, "Enter Order Message" },
    { NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_REPLACE_ORDER, "Replace Order Message" },
    { NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_CANCEL_ORDER, "Cancel Order Message" },
    { NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_MODIFY_ORDER, "Modify Order Message" },
    { NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_ACCOUNT_QUERY, "Account Query Message" },
    { NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_MASS_CANCEL_REQUEST, "Mass Cancel Request Message" },
    { NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_DISABLE_ORDER_ENTRY_REQUEST, "Disable Order Entry Request Message" },
    { NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_ENABLE_ORDER_ENTRY_REQUEST, "Enable Order Entry Request Message" },
    { 0, NULL }
};

/* Unsequenced Message: dispatch on unsequenced_message_type */
static unsigned
dissect_nsmequities_orders_unsequenced_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t unsequenced_message_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, unsequenced_message_type, nsmequities_orders_unsequenced_message_messages, "Unknown (%u)"));

    switch (unsequenced_message_type) {
    case NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_ENTER_ORDER:
        return dissect_nsmequities_orders_enter_order(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_REPLACE_ORDER:
        return dissect_nsmequities_orders_replace_order(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_CANCEL_ORDER:
        return dissect_nsmequities_orders_cancel_order(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_MODIFY_ORDER:
        return dissect_nsmequities_orders_modify_order(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_ACCOUNT_QUERY:
        return dissect_nsmequities_orders_account_query(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_MASS_CANCEL_REQUEST:
        return dissect_nsmequities_orders_mass_cancel_request(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_DISABLE_ORDER_ENTRY_REQUEST:
        return dissect_nsmequities_orders_disable_order_entry_request(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_ENABLE_ORDER_ENTRY_REQUEST:
        return dissect_nsmequities_orders_enable_order_entry_request(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_orders_unsequenced_message_messages_v422018[] = {
    { NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_ENTER_ORDER, "Enter Order Message" },
    { NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_REPLACE_ORDER, "Replace Order Message" },
    { NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_CANCEL_ORDER, "Cancel Order Message" },
    { NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_MODIFY_ORDER, "Modify Order Message" },
    { NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_TRADE_NOW, "Trade Now Message" },
    { 0, NULL }
};

/* Unsequenced Message: dispatch on unsequenced_message_type */
static unsigned
dissect_nsmequities_orders_unsequenced_message_v422018(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t unsequenced_message_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, unsequenced_message_type, nsmequities_orders_unsequenced_message_messages_v422018, "Unknown (%u)"));

    switch (unsequenced_message_type) {
    case NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_ENTER_ORDER:
        return dissect_nsmequities_orders_enter_order_v422018(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_REPLACE_ORDER:
        return dissect_nsmequities_orders_replace_order_v422018(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_CANCEL_ORDER:
        return dissect_nsmequities_orders_cancel_order_v422018(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_MODIFY_ORDER:
        return dissect_nsmequities_orders_modify_order_v422018(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_TRADE_NOW:
        return dissect_nsmequities_orders_trade_now(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_orders_enter_order_optional_value_messages[] = {
    { NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_FIRM, "Firm" },
    { NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_MINQTY, "Min Qty" },
    { NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_CUSTOMERTYPE, "Customer Type" },
    { NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_MAXFLOOR, "Max Floor" },
    { NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_PRICETYPE, "Price Type" },
    { NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_PEGOFFSET, "Peg Offset" },
    { NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_DISCRETIONPRICE, "Discretion Price" },
    { NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_DISCRETIONPRICETYPE, "Discretion Price Type" },
    { NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_DISCRETIONPEGOFFSET, "Discretion Peg Offset" },
    { NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_POSTONLY, "Post Only" },
    { NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_RANDOMRESERVES, "Random Reserves" },
    { NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_EXPIRETIME, "Expire Time" },
    { NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_TRADENOW, "Trade Now" },
    { NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_HANDLEINST, "Handle Inst" },
    { NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_GROUP_ID, "Group Id" },
    { NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_SHARES_LOCATED, "Shares Located" },
    { NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_LOCATE_BROKER, "Locate Broker" },
    { NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_USERREFIDX, "User Ref Idx" },
    { NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_AIQ_STRATEGY, "Aiq Strategy" },
    { NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_AIQ_GROUP_ID, "Aiq Group Id" },
    { 0, NULL }
};

/* Enter Order Optional Value: dispatch on enter_order_optional_field */
static unsigned
dissect_nsmequities_orders_enter_order_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t enter_order_optional_field)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, enter_order_optional_field, nsmequities_orders_enter_order_optional_value_messages, "Unknown (%u)"));

    switch (enter_order_optional_field) {
    case NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_FIRM:
        return parse_nsmequities_orders_firm(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_MINQTY:
        return parse_nsmequities_orders_min_qty(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_CUSTOMERTYPE:
        return parse_nsmequities_orders_customer_type(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_MAXFLOOR:
        return parse_nsmequities_orders_max_floor(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_PRICETYPE:
        return parse_nsmequities_orders_price_type(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_PEGOFFSET:
        return parse_nsmequities_orders_peg_offset(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_DISCRETIONPRICE:
        return parse_nsmequities_orders_discretion_price(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_DISCRETIONPRICETYPE:
        return parse_nsmequities_orders_discretion_price_type(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_DISCRETIONPEGOFFSET:
        return parse_nsmequities_orders_discretion_peg_offset(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_POSTONLY:
        return parse_nsmequities_orders_post_only(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_RANDOMRESERVES:
        return parse_nsmequities_orders_random_reserves(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_EXPIRETIME:
        return parse_nsmequities_orders_expire_time(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_TRADENOW:
        return parse_nsmequities_orders_trade_now(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_HANDLEINST:
        return parse_nsmequities_orders_handle_inst(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_GROUP_ID:
        return parse_nsmequities_orders_group_id(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_SHARES_LOCATED:
        return parse_nsmequities_orders_shares_located(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_LOCATE_BROKER:
        return parse_nsmequities_orders_locate_broker(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_USERREFIDX:
        return parse_nsmequities_orders_user_ref_idx(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_AIQ_STRATEGY:
        return parse_nsmequities_orders_aiq_strategy(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_AIQ_GROUP_ID:
        return parse_nsmequities_orders_aiq_group_id(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_orders_replace_order_optional_value_messages[] = {
    { NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_MINQTY, "Min Qty" },
    { NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_MAXFLOOR, "Max Floor" },
    { NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_PRICETYPE, "Price Type" },
    { NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_POSTONLY, "Post Only" },
    { NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_EXPIRETIME, "Expire Time" },
    { NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_TRADENOW, "Trade Now" },
    { NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_HANDLEINST, "Handle Inst" },
    { NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_RANDOMRESERVES, "Random Reserves" },
    { NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_PEGOFFSET, "Peg Offset" },
    { NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_DISCRETIONPRICE, "Discretion Price" },
    { NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_DISCRETIONPRICETYPE, "Discretion Price Type" },
    { NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_DISCRETIONPEGOFFSET, "Discretion Peg Offset" },
    { NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_SHARES_LOCATED, "Shares Located" },
    { NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_LOCATE_BROKER, "Locate Broker" },
    { NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_USERREFIDX, "User Ref Idx" },
    { NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_SIDE, "Side" },
    { NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_AIQ_STRATEGY, "Aiq Strategy" },
    { NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_AIQ_GROUP_ID, "Aiq Group Id" },
    { 0, NULL }
};

/* Replace Order Optional Value: dispatch on replace_order_optional_field */
static unsigned
dissect_nsmequities_orders_replace_order_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t replace_order_optional_field)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, replace_order_optional_field, nsmequities_orders_replace_order_optional_value_messages, "Unknown (%u)"));

    switch (replace_order_optional_field) {
    case NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_MINQTY:
        return parse_nsmequities_orders_min_qty(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_MAXFLOOR:
        return parse_nsmequities_orders_max_floor(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_PRICETYPE:
        return parse_nsmequities_orders_price_type(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_POSTONLY:
        return parse_nsmequities_orders_post_only(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_EXPIRETIME:
        return parse_nsmequities_orders_expire_time(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_TRADENOW:
        return parse_nsmequities_orders_trade_now(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_HANDLEINST:
        return parse_nsmequities_orders_handle_inst(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_RANDOMRESERVES:
        return parse_nsmequities_orders_random_reserves(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_PEGOFFSET:
        return parse_nsmequities_orders_peg_offset(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_DISCRETIONPRICE:
        return parse_nsmequities_orders_discretion_price(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_DISCRETIONPRICETYPE:
        return parse_nsmequities_orders_discretion_price_type(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_DISCRETIONPEGOFFSET:
        return parse_nsmequities_orders_discretion_peg_offset(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_SHARES_LOCATED:
        return parse_nsmequities_orders_shares_located(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_LOCATE_BROKER:
        return parse_nsmequities_orders_locate_broker(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_USERREFIDX:
        return parse_nsmequities_orders_user_ref_idx(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_SIDE:
        return parse_nsmequities_orders_side(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_AIQ_STRATEGY:
        return parse_nsmequities_orders_aiq_strategy(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_AIQ_GROUP_ID:
        return parse_nsmequities_orders_aiq_group_id(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_orders_cancel_order_optional_value_messages[] = {
    { NSMEQUITIES_ORDERS_CANCEL_ORDER_OPTIONAL_FIELD_USERREFIDX, "User Ref Idx" },
    { 0, NULL }
};

/* Cancel Order Optional Value: dispatch on cancel_order_optional_field */
static unsigned
dissect_nsmequities_orders_cancel_order_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t cancel_order_optional_field)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, cancel_order_optional_field, nsmequities_orders_cancel_order_optional_value_messages, "Unknown (%u)"));

    switch (cancel_order_optional_field) {
    case NSMEQUITIES_ORDERS_CANCEL_ORDER_OPTIONAL_FIELD_USERREFIDX:
        return parse_nsmequities_orders_user_ref_idx(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_orders_modify_order_optional_value_messages[] = {
    { NSMEQUITIES_ORDERS_MODIFY_ORDER_OPTIONAL_FIELD_USERREFIDX, "User Ref Idx" },
    { NSMEQUITIES_ORDERS_MODIFY_ORDER_OPTIONAL_FIELD_SHARES_LOCATED, "Shares Located" },
    { NSMEQUITIES_ORDERS_MODIFY_ORDER_OPTIONAL_FIELD_LOCATE_BROKER, "Locate Broker" },
    { 0, NULL }
};

/* Modify Order Optional Value: dispatch on modify_order_optional_field */
static unsigned
dissect_nsmequities_orders_modify_order_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t modify_order_optional_field)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, modify_order_optional_field, nsmequities_orders_modify_order_optional_value_messages, "Unknown (%u)"));

    switch (modify_order_optional_field) {
    case NSMEQUITIES_ORDERS_MODIFY_ORDER_OPTIONAL_FIELD_USERREFIDX:
        return parse_nsmequities_orders_user_ref_idx(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_MODIFY_ORDER_OPTIONAL_FIELD_SHARES_LOCATED:
        return parse_nsmequities_orders_shares_located(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_MODIFY_ORDER_OPTIONAL_FIELD_LOCATE_BROKER:
        return parse_nsmequities_orders_locate_broker(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_orders_account_query_optional_value_messages[] = {
    { NSMEQUITIES_ORDERS_ACCOUNT_QUERY_OPTIONAL_FIELD_USERREFIDX, "User Ref Idx" },
    { 0, NULL }
};

/* Account Query Optional Value: dispatch on account_query_optional_field */
static unsigned
dissect_nsmequities_orders_account_query_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t account_query_optional_field)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, account_query_optional_field, nsmequities_orders_account_query_optional_value_messages, "Unknown (%u)"));

    switch (account_query_optional_field) {
    case NSMEQUITIES_ORDERS_ACCOUNT_QUERY_OPTIONAL_FIELD_USERREFIDX:
        return parse_nsmequities_orders_user_ref_idx(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_orders_mass_cancel_request_optional_value_messages[] = {
    { NSMEQUITIES_ORDERS_MASS_CANCEL_REQUEST_OPTIONAL_FIELD_SIDE, "Side" },
    { NSMEQUITIES_ORDERS_MASS_CANCEL_REQUEST_OPTIONAL_FIELD_GROUP_ID, "Group Id" },
    { NSMEQUITIES_ORDERS_MASS_CANCEL_REQUEST_OPTIONAL_FIELD_USERREFIDX, "User Ref Idx" },
    { 0, NULL }
};

/* Mass Cancel Request Optional Value: dispatch on mass_cancel_request_optional_field */
static unsigned
dissect_nsmequities_orders_mass_cancel_request_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t mass_cancel_request_optional_field)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, mass_cancel_request_optional_field, nsmequities_orders_mass_cancel_request_optional_value_messages, "Unknown (%u)"));

    switch (mass_cancel_request_optional_field) {
    case NSMEQUITIES_ORDERS_MASS_CANCEL_REQUEST_OPTIONAL_FIELD_SIDE:
        return parse_nsmequities_orders_side(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_MASS_CANCEL_REQUEST_OPTIONAL_FIELD_GROUP_ID:
        return parse_nsmequities_orders_group_id(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_MASS_CANCEL_REQUEST_OPTIONAL_FIELD_USERREFIDX:
        return parse_nsmequities_orders_user_ref_idx(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_orders_disable_order_entry_request_optional_value_messages[] = {
    { NSMEQUITIES_ORDERS_DISABLE_ORDER_ENTRY_REQUEST_OPTIONAL_FIELD_USERREFIDX, "User Ref Idx" },
    { 0, NULL }
};

/* Disable Order Entry Request Optional Value: dispatch on disable_order_entry_request_optional_field */
static unsigned
dissect_nsmequities_orders_disable_order_entry_request_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t disable_order_entry_request_optional_field)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, disable_order_entry_request_optional_field, nsmequities_orders_disable_order_entry_request_optional_value_messages, "Unknown (%u)"));

    switch (disable_order_entry_request_optional_field) {
    case NSMEQUITIES_ORDERS_DISABLE_ORDER_ENTRY_REQUEST_OPTIONAL_FIELD_USERREFIDX:
        return parse_nsmequities_orders_user_ref_idx(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_orders_enable_order_entry_request_optional_value_messages[] = {
    { NSMEQUITIES_ORDERS_ENABLE_ORDER_ENTRY_REQUEST_OPTIONAL_FIELD_USERREFIDX, "User Ref Idx" },
    { 0, NULL }
};

/* Enable Order Entry Request Optional Value: dispatch on enable_order_entry_request_optional_field */
static unsigned
dissect_nsmequities_orders_enable_order_entry_request_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t enable_order_entry_request_optional_field)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, enable_order_entry_request_optional_field, nsmequities_orders_enable_order_entry_request_optional_value_messages, "Unknown (%u)"));

    switch (enable_order_entry_request_optional_field) {
    case NSMEQUITIES_ORDERS_ENABLE_ORDER_ENTRY_REQUEST_OPTIONAL_FIELD_USERREFIDX:
        return parse_nsmequities_orders_user_ref_idx(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_orders_server_packet_messages[] = {
    { NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_DEBUG_PACKET, "Debug Packet" },
    { NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET, "Login Accepted Packet" },
    { NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET, "Login Rejected Packet" },
    { NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET, "Sequenced Data Packet" },
    { NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_SERVER_HEARTBEAT_PACKET, "Server Heartbeat" },
    { NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_END_OF_SESSION_PACKET, "End Of Session" },
    { 0, NULL }
};

/* Server Payload: dispatch on server_packet_type */
static unsigned
dissect_nsmequities_orders_server_packet_server_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t server_packet_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, server_packet_type, nsmequities_orders_server_packet_messages, "Unknown (%u)"));

    switch (server_packet_type) {
    case NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_DEBUG_PACKET:
        return dissect_nsmequities_orders_debug_packet(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET:
        return dissect_nsmequities_orders_login_accepted_packet(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET:
        return dissect_nsmequities_orders_login_rejected_packet(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET:
        return dissect_nsmequities_orders_sequenced_data_packet(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_SERVER_HEARTBEAT_PACKET: /* Server Heartbeat */
        return offset;
    case NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_END_OF_SESSION_PACKET: /* End Of Session */
        return offset;
    }

    return offset;
}

static const value_string nsmequities_orders_server_packet_messages_v422018[] = {
    { NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_DEBUG_PACKET, "Debug Packet" },
    { NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET, "Login Accepted Packet" },
    { NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET, "Login Rejected Packet" },
    { NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET, "Sequenced Data Packet" },
    { NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_SERVER_HEARTBEAT_PACKET, "Server Heartbeat" },
    { NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_END_OF_SESSION_PACKET, "End Of Session" },
    { 0, NULL }
};

/* Server Payload: dispatch on server_packet_type */
static unsigned
dissect_nsmequities_orders_server_packet_server_payload_v422018(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t server_packet_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, server_packet_type, nsmequities_orders_server_packet_messages_v422018, "Unknown (%u)"));

    switch (server_packet_type) {
    case NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_DEBUG_PACKET:
        return dissect_nsmequities_orders_debug_packet(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET:
        return dissect_nsmequities_orders_login_accepted_packet(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET:
        return dissect_nsmequities_orders_login_rejected_packet(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET:
        return dissect_nsmequities_orders_sequenced_data_packet_v422018(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_SERVER_HEARTBEAT_PACKET: /* Server Heartbeat */
        return offset;
    case NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_END_OF_SESSION_PACKET: /* End Of Session */
        return offset;
    }

    return offset;
}

static const value_string nsmequities_orders_sequenced_message_messages[] = {
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_SYSTEM_EVENT, "System Event Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_ORDER_ACCEPTED, "Order Accepted Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_REPLACED, "Replaced Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_CANCELED, "Canceled Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_AIQ_CANCELED, "Aiq Canceled Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_ORDER_EXECUTED, "Order Executed Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_BROKEN_TRADE, "Broken Trade Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_REJECTED_ORDER, "Rejected Order Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_CANCEL_PENDING, "Cancel Pending Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_CANCEL_REJECT, "Cancel Reject Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_ORDER_PRIORITY_UPDATE, "Order Priority Update Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_ORDER_MODIFIED, "Order Modified Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_ORDER_RESTATED, "Order Restated Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_ACCOUNT_QUERY_RESPONSE, "Account Query Response Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_MASS_CANCEL_RESPONSE, "Mass Cancel Response Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_DISABLE_ORDER_ENTRY_RESPONSE, "Disable Order Entry Response Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_ENABLE_ORDER_ENTRY_RESPONSE, "Enable Order Entry Response Message" },
    { 0, NULL }
};

/* Sequenced Message: dispatch on sequenced_message_type */
static unsigned
dissect_nsmequities_orders_sequenced_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t sequenced_message_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, sequenced_message_type, nsmequities_orders_sequenced_message_messages, "Unknown (%u)"));

    switch (sequenced_message_type) {
    case NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_SYSTEM_EVENT:
        return dissect_nsmequities_orders_system_event(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_ORDER_ACCEPTED:
        return dissect_nsmequities_orders_order_accepted(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_REPLACED:
        return dissect_nsmequities_orders_replaced(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_CANCELED:
        return dissect_nsmequities_orders_canceled(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_AIQ_CANCELED:
        return dissect_nsmequities_orders_aiq_canceled(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_ORDER_EXECUTED:
        return dissect_nsmequities_orders_order_executed(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_BROKEN_TRADE:
        return dissect_nsmequities_orders_broken_trade(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_REJECTED_ORDER:
        return dissect_nsmequities_orders_rejected_order(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_CANCEL_PENDING:
        return dissect_nsmequities_orders_cancel_pending(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_CANCEL_REJECT:
        return dissect_nsmequities_orders_cancel_reject(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_ORDER_PRIORITY_UPDATE:
        return dissect_nsmequities_orders_order_priority_update(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_ORDER_MODIFIED:
        return dissect_nsmequities_orders_order_modified(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_ORDER_RESTATED:
        return dissect_nsmequities_orders_order_restated(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_ACCOUNT_QUERY_RESPONSE:
        return dissect_nsmequities_orders_account_query_response(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_MASS_CANCEL_RESPONSE:
        return dissect_nsmequities_orders_mass_cancel_response(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_DISABLE_ORDER_ENTRY_RESPONSE:
        return dissect_nsmequities_orders_disable_order_entry_response(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_ENABLE_ORDER_ENTRY_RESPONSE:
        return dissect_nsmequities_orders_enable_order_entry_response(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_orders_sequenced_message_messages_v422018[] = {
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_SYSTEM_EVENT, "System Event Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_ORDER_ACCEPTED, "Accepted Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_REPLACED, "Replaced Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_CANCELED, "Canceled Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_AIQ_CANCELED, "Aiq Cancelled Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_ORDER_EXECUTED, "Executed Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_BROKEN_TRADE, "Broken Trade Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_DISABLE_ORDER_ENTRY_RESPONSE, "Executed With Reference Price Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_TRADE_CORRECTION, "Trade Correction Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_REJECTED_ORDER, "Rejected Order Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_CANCEL_PENDING, "Cancel Pending Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_CANCEL_REJECT, "Cancel Reject Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_ORDER_PRIORITY_UPDATE, "Order Priority Update Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_ORDER_MODIFIED, "Order Modified Message" },
    { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_SEQUENCED_TRADE_NOW, "Sequenced Trade Now Message" },
    { 0, NULL }
};

/* Sequenced Message: dispatch on sequenced_message_type */
static unsigned
dissect_nsmequities_orders_sequenced_message_v422018(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t sequenced_message_type)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, sequenced_message_type, nsmequities_orders_sequenced_message_messages_v422018, "Unknown (%u)"));

    switch (sequenced_message_type) {
    case NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_SYSTEM_EVENT:
        return dissect_nsmequities_orders_system_event_v422018(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_ORDER_ACCEPTED:
        return dissect_nsmequities_orders_accepted(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_REPLACED:
        return dissect_nsmequities_orders_replaced_v422018(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_CANCELED:
        return dissect_nsmequities_orders_canceled_v422018(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_AIQ_CANCELED:
        return dissect_nsmequities_orders_aiq_cancelled(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_ORDER_EXECUTED:
        return dissect_nsmequities_orders_executed(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_BROKEN_TRADE:
        return dissect_nsmequities_orders_broken_trade_v422018(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_DISABLE_ORDER_ENTRY_RESPONSE:
        return dissect_nsmequities_orders_executed_with_reference_price(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_TRADE_CORRECTION:
        return dissect_nsmequities_orders_trade_correction(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_REJECTED_ORDER:
        return dissect_nsmequities_orders_rejected_order_v422018(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_CANCEL_PENDING:
        return dissect_nsmequities_orders_cancel_pending_v422018(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_CANCEL_REJECT:
        return dissect_nsmequities_orders_cancel_reject_v422018(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_ORDER_PRIORITY_UPDATE:
        return dissect_nsmequities_orders_order_priority_update_v422018(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_ORDER_MODIFIED:
        return dissect_nsmequities_orders_order_modified_v422018(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_SEQUENCED_TRADE_NOW:
        return dissect_nsmequities_orders_sequenced_trade_now(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_orders_order_accepted_optional_value_messages[] = {
    { NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_FIRM, "Firm" },
    { NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_MINQTY, "Min Qty" },
    { NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_CUSTOMERTYPE, "Customer Type" },
    { NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_MAXFLOOR, "Max Floor" },
    { NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_PRICETYPE, "Price Type" },
    { NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_PEGOFFSET, "Peg Offset" },
    { NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_DISCRETIONPRICE, "Discretion Price" },
    { NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_DISCRETIONPRICETYPE, "Discretion Price Type" },
    { NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_DISCRETIONPEGOFFSET, "Discretion Peg Offset" },
    { NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_POSTONLY, "Post Only" },
    { NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_RANDOMRESERVES, "Random Reserves" },
    { NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_ROUTE, "Route" },
    { NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_EXPIRETIME, "Expire Time" },
    { NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_TRADENOW, "Trade Now" },
    { NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_HANDLEINST, "Handle Inst" },
    { NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_BBO_WEIGHT_INDICATOR, "Bbo Weight Indicator" },
    { NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_GROUP_ID, "Group Id" },
    { NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_SHARES_LOCATED, "Shares Located" },
    { NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_USERREFIDX, "User Ref Idx" },
    { NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_AIQ_STRATEGY, "Aiq Strategy" },
    { NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_AIQ_GROUP_ID, "Aiq Group Id" },
    { 0, NULL }
};

/* Order Accepted Optional Value: dispatch on order_accepted_optional_field */
static unsigned
dissect_nsmequities_orders_order_accepted_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t order_accepted_optional_field)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, order_accepted_optional_field, nsmequities_orders_order_accepted_optional_value_messages, "Unknown (%u)"));

    switch (order_accepted_optional_field) {
    case NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_FIRM:
        return parse_nsmequities_orders_firm(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_MINQTY:
        return parse_nsmequities_orders_min_qty(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_CUSTOMERTYPE:
        return parse_nsmequities_orders_customer_type(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_MAXFLOOR:
        return parse_nsmequities_orders_max_floor(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_PRICETYPE:
        return parse_nsmequities_orders_price_type(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_PEGOFFSET:
        return parse_nsmequities_orders_peg_offset(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_DISCRETIONPRICE:
        return parse_nsmequities_orders_discretion_price(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_DISCRETIONPRICETYPE:
        return parse_nsmequities_orders_discretion_price_type(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_DISCRETIONPEGOFFSET:
        return parse_nsmequities_orders_discretion_peg_offset(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_POSTONLY:
        return parse_nsmequities_orders_post_only(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_RANDOMRESERVES:
        return parse_nsmequities_orders_random_reserves(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_ROUTE:
        return parse_nsmequities_orders_route(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_EXPIRETIME:
        return parse_nsmequities_orders_expire_time(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_TRADENOW:
        return parse_nsmequities_orders_trade_now(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_HANDLEINST:
        return parse_nsmequities_orders_handle_inst(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_BBO_WEIGHT_INDICATOR:
        return parse_nsmequities_orders_bbo_weight_indicator(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_GROUP_ID:
        return parse_nsmequities_orders_group_id(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_SHARES_LOCATED:
        return parse_nsmequities_orders_shares_located(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_USERREFIDX:
        return parse_nsmequities_orders_user_ref_idx(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_AIQ_STRATEGY:
        return parse_nsmequities_orders_aiq_strategy(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_AIQ_GROUP_ID:
        return parse_nsmequities_orders_aiq_group_id(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_orders_replaced_message_optional_value_messages[] = {
    { NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_FIRM, "Firm" },
    { NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_MINQTY, "Min Qty" },
    { NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_MAXFLOOR, "Max Floor" },
    { NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_PRICETYPE, "Price Type" },
    { NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_POSTONLY, "Post Only" },
    { NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_EXPIRETIME, "Expire Time" },
    { NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_TRADENOW, "Trade Now" },
    { NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_HANDLEINST, "Handle Inst" },
    { NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_BBO_WEIGHT_INDICATOR, "Bbo Weight Indicator" },
    { NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_USERREFIDX, "User Ref Idx" },
    { NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_AIQ_STRATEGY, "Aiq Strategy" },
    { NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_AIQ_GROUP_ID, "Aiq Group Id" },
    { 0, NULL }
};

/* Replaced Message Optional Value: dispatch on replaced_message_optional_field */
static unsigned
dissect_nsmequities_orders_replaced_message_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t replaced_message_optional_field)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, replaced_message_optional_field, nsmequities_orders_replaced_message_optional_value_messages, "Unknown (%u)"));

    switch (replaced_message_optional_field) {
    case NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_FIRM:
        return parse_nsmequities_orders_firm(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_MINQTY:
        return parse_nsmequities_orders_min_qty(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_MAXFLOOR:
        return parse_nsmequities_orders_max_floor(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_PRICETYPE:
        return parse_nsmequities_orders_price_type(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_POSTONLY:
        return parse_nsmequities_orders_post_only(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_EXPIRETIME:
        return parse_nsmequities_orders_expire_time(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_TRADENOW:
        return parse_nsmequities_orders_trade_now(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_HANDLEINST:
        return parse_nsmequities_orders_handle_inst(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_BBO_WEIGHT_INDICATOR:
        return parse_nsmequities_orders_bbo_weight_indicator(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_USERREFIDX:
        return parse_nsmequities_orders_user_ref_idx(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_AIQ_STRATEGY:
        return parse_nsmequities_orders_aiq_strategy(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_AIQ_GROUP_ID:
        return parse_nsmequities_orders_aiq_group_id(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_orders_canceled_message_optional_value_messages[] = {
    { NSMEQUITIES_ORDERS_CANCELED_MESSAGE_OPTIONAL_FIELD_USERREFIDX, "User Ref Idx" },
    { 0, NULL }
};

/* Canceled Message Optional Value: dispatch on canceled_message_optional_field */
static unsigned
dissect_nsmequities_orders_canceled_message_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t canceled_message_optional_field)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, canceled_message_optional_field, nsmequities_orders_canceled_message_optional_value_messages, "Unknown (%u)"));

    switch (canceled_message_optional_field) {
    case NSMEQUITIES_ORDERS_CANCELED_MESSAGE_OPTIONAL_FIELD_USERREFIDX:
        return parse_nsmequities_orders_user_ref_idx(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_orders_aiq_canceled_optional_value_messages[] = {
    { NSMEQUITIES_ORDERS_AIQ_CANCELED_OPTIONAL_FIELD_USERREFIDX, "User Ref Idx" },
    { 0, NULL }
};

/* Aiq Canceled Optional Value: dispatch on aiq_canceled_optional_field */
static unsigned
dissect_nsmequities_orders_aiq_canceled_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t aiq_canceled_optional_field)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, aiq_canceled_optional_field, nsmequities_orders_aiq_canceled_optional_value_messages, "Unknown (%u)"));

    switch (aiq_canceled_optional_field) {
    case NSMEQUITIES_ORDERS_AIQ_CANCELED_OPTIONAL_FIELD_USERREFIDX:
        return parse_nsmequities_orders_user_ref_idx(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_orders_order_executed_optional_value_messages[] = {
    { NSMEQUITIES_ORDERS_ORDER_EXECUTED_OPTIONAL_FIELD_USERREFIDX, "User Ref Idx" },
    { 0, NULL }
};

/* Order Executed Optional Value: dispatch on order_executed_optional_field */
static unsigned
dissect_nsmequities_orders_order_executed_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t order_executed_optional_field)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, order_executed_optional_field, nsmequities_orders_order_executed_optional_value_messages, "Unknown (%u)"));

    switch (order_executed_optional_field) {
    case NSMEQUITIES_ORDERS_ORDER_EXECUTED_OPTIONAL_FIELD_USERREFIDX:
        return parse_nsmequities_orders_user_ref_idx(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_orders_broken_trade_optional_value_messages[] = {
    { NSMEQUITIES_ORDERS_BROKEN_TRADE_OPTIONAL_FIELD_USERREFIDX, "User Ref Idx" },
    { 0, NULL }
};

/* Broken Trade Optional Value: dispatch on broken_trade_optional_field */
static unsigned
dissect_nsmequities_orders_broken_trade_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t broken_trade_optional_field)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, broken_trade_optional_field, nsmequities_orders_broken_trade_optional_value_messages, "Unknown (%u)"));

    switch (broken_trade_optional_field) {
    case NSMEQUITIES_ORDERS_BROKEN_TRADE_OPTIONAL_FIELD_USERREFIDX:
        return parse_nsmequities_orders_user_ref_idx(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_orders_rejected_order_optional_value_messages[] = {
    { NSMEQUITIES_ORDERS_REJECTED_ORDER_OPTIONAL_FIELD_USERREFIDX, "User Ref Idx" },
    { 0, NULL }
};

/* Rejected Order Optional Value: dispatch on rejected_order_optional_field */
static unsigned
dissect_nsmequities_orders_rejected_order_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t rejected_order_optional_field)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, rejected_order_optional_field, nsmequities_orders_rejected_order_optional_value_messages, "Unknown (%u)"));

    switch (rejected_order_optional_field) {
    case NSMEQUITIES_ORDERS_REJECTED_ORDER_OPTIONAL_FIELD_USERREFIDX:
        return parse_nsmequities_orders_user_ref_idx(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_orders_cancel_pending_optional_value_messages[] = {
    { NSMEQUITIES_ORDERS_CANCEL_PENDING_OPTIONAL_FIELD_USERREFIDX, "User Ref Idx" },
    { 0, NULL }
};

/* Cancel Pending Optional Value: dispatch on cancel_pending_optional_field */
static unsigned
dissect_nsmequities_orders_cancel_pending_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t cancel_pending_optional_field)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, cancel_pending_optional_field, nsmequities_orders_cancel_pending_optional_value_messages, "Unknown (%u)"));

    switch (cancel_pending_optional_field) {
    case NSMEQUITIES_ORDERS_CANCEL_PENDING_OPTIONAL_FIELD_USERREFIDX:
        return parse_nsmequities_orders_user_ref_idx(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_orders_cancel_reject_optional_value_messages[] = {
    { NSMEQUITIES_ORDERS_CANCEL_REJECT_OPTIONAL_FIELD_USERREFIDX, "User Ref Idx" },
    { 0, NULL }
};

/* Cancel Reject Optional Value: dispatch on cancel_reject_optional_field */
static unsigned
dissect_nsmequities_orders_cancel_reject_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t cancel_reject_optional_field)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, cancel_reject_optional_field, nsmequities_orders_cancel_reject_optional_value_messages, "Unknown (%u)"));

    switch (cancel_reject_optional_field) {
    case NSMEQUITIES_ORDERS_CANCEL_REJECT_OPTIONAL_FIELD_USERREFIDX:
        return parse_nsmequities_orders_user_ref_idx(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_orders_order_priority_update_optional_value_messages[] = {
    { NSMEQUITIES_ORDERS_ORDER_PRIORITY_UPDATE_OPTIONAL_FIELD_USERREFIDX, "User Ref Idx" },
    { 0, NULL }
};

/* Order Priority Update Optional Value: dispatch on order_priority_update_optional_field */
static unsigned
dissect_nsmequities_orders_order_priority_update_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t order_priority_update_optional_field)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, order_priority_update_optional_field, nsmequities_orders_order_priority_update_optional_value_messages, "Unknown (%u)"));

    switch (order_priority_update_optional_field) {
    case NSMEQUITIES_ORDERS_ORDER_PRIORITY_UPDATE_OPTIONAL_FIELD_USERREFIDX:
        return parse_nsmequities_orders_user_ref_idx(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_orders_order_modified_optional_value_messages[] = {
    { NSMEQUITIES_ORDERS_ORDER_MODIFIED_OPTIONAL_FIELD_USERREFIDX, "User Ref Idx" },
    { NSMEQUITIES_ORDERS_ORDER_MODIFIED_OPTIONAL_FIELD_SHARES_LOCATED, "Shares Located" },
    { NSMEQUITIES_ORDERS_ORDER_MODIFIED_OPTIONAL_FIELD_LOCATE_BROKER, "Locate Broker" },
    { 0, NULL }
};

/* Order Modified Optional Value: dispatch on order_modified_optional_field */
static unsigned
dissect_nsmequities_orders_order_modified_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t order_modified_optional_field)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, order_modified_optional_field, nsmequities_orders_order_modified_optional_value_messages, "Unknown (%u)"));

    switch (order_modified_optional_field) {
    case NSMEQUITIES_ORDERS_ORDER_MODIFIED_OPTIONAL_FIELD_USERREFIDX:
        return parse_nsmequities_orders_user_ref_idx(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_ORDER_MODIFIED_OPTIONAL_FIELD_SHARES_LOCATED:
        return parse_nsmequities_orders_shares_located(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_ORDER_MODIFIED_OPTIONAL_FIELD_LOCATE_BROKER:
        return parse_nsmequities_orders_locate_broker(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_orders_order_restated_optional_value_messages[] = {
    { NSMEQUITIES_ORDERS_ORDER_RESTATED_OPTIONAL_FIELD_DISPLAY_QUANTITY, "Display Quantity" },
    { NSMEQUITIES_ORDERS_ORDER_RESTATED_OPTIONAL_FIELD_DISPLAY_PRICE, "Display Price" },
    { NSMEQUITIES_ORDERS_ORDER_RESTATED_OPTIONAL_FIELD_SECONDARYORDREFNUM, "Secondary Ord Ref Num" },
    { NSMEQUITIES_ORDERS_ORDER_RESTATED_OPTIONAL_FIELD_USERREFIDX, "User Ref Idx" },
    { 0, NULL }
};

/* Order Restated Optional Value: dispatch on order_restated_optional_field */
static unsigned
dissect_nsmequities_orders_order_restated_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t order_restated_optional_field)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, order_restated_optional_field, nsmequities_orders_order_restated_optional_value_messages, "Unknown (%u)"));

    switch (order_restated_optional_field) {
    case NSMEQUITIES_ORDERS_ORDER_RESTATED_OPTIONAL_FIELD_DISPLAY_QUANTITY:
        return parse_nsmequities_orders_display_quantity(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_ORDER_RESTATED_OPTIONAL_FIELD_DISPLAY_PRICE:
        return parse_nsmequities_orders_display_price(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_ORDER_RESTATED_OPTIONAL_FIELD_SECONDARYORDREFNUM:
        return parse_nsmequities_orders_secondary_ord_ref_num(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_ORDER_RESTATED_OPTIONAL_FIELD_USERREFIDX:
        return parse_nsmequities_orders_user_ref_idx(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_orders_account_query_response_optional_value_messages[] = {
    { NSMEQUITIES_ORDERS_ACCOUNT_QUERY_RESPONSE_OPTIONAL_FIELD_USERREFIDX, "User Ref Idx" },
    { 0, NULL }
};

/* Account Query Response Optional Value: dispatch on account_query_response_optional_field */
static unsigned
dissect_nsmequities_orders_account_query_response_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t account_query_response_optional_field)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, account_query_response_optional_field, nsmequities_orders_account_query_response_optional_value_messages, "Unknown (%u)"));

    switch (account_query_response_optional_field) {
    case NSMEQUITIES_ORDERS_ACCOUNT_QUERY_RESPONSE_OPTIONAL_FIELD_USERREFIDX:
        return parse_nsmequities_orders_user_ref_idx(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_orders_mass_cancel_response_optional_value_messages[] = {
    { NSMEQUITIES_ORDERS_MASS_CANCEL_RESPONSE_OPTIONAL_FIELD_SIDE, "Side" },
    { NSMEQUITIES_ORDERS_MASS_CANCEL_RESPONSE_OPTIONAL_FIELD_GROUP_ID, "Group Id" },
    { NSMEQUITIES_ORDERS_MASS_CANCEL_RESPONSE_OPTIONAL_FIELD_USERREFIDX, "User Ref Idx" },
    { 0, NULL }
};

/* Mass Cancel Response Optional Value: dispatch on mass_cancel_response_optional_field */
static unsigned
dissect_nsmequities_orders_mass_cancel_response_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t mass_cancel_response_optional_field)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, mass_cancel_response_optional_field, nsmequities_orders_mass_cancel_response_optional_value_messages, "Unknown (%u)"));

    switch (mass_cancel_response_optional_field) {
    case NSMEQUITIES_ORDERS_MASS_CANCEL_RESPONSE_OPTIONAL_FIELD_SIDE:
        return parse_nsmequities_orders_side(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_MASS_CANCEL_RESPONSE_OPTIONAL_FIELD_GROUP_ID:
        return parse_nsmequities_orders_group_id(tvb, pinfo, tree, offset);
    case NSMEQUITIES_ORDERS_MASS_CANCEL_RESPONSE_OPTIONAL_FIELD_USERREFIDX:
        return parse_nsmequities_orders_user_ref_idx(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_orders_disable_order_entry_response_optional_value_messages[] = {
    { NSMEQUITIES_ORDERS_DISABLE_ORDER_ENTRY_RESPONSE_OPTIONAL_FIELD_USERREFIDX, "User Ref Idx" },
    { 0, NULL }
};

/* Disable Order Entry Response Optional Value: dispatch on disable_order_entry_response_optional_field */
static unsigned
dissect_nsmequities_orders_disable_order_entry_response_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t disable_order_entry_response_optional_field)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, disable_order_entry_response_optional_field, nsmequities_orders_disable_order_entry_response_optional_value_messages, "Unknown (%u)"));

    switch (disable_order_entry_response_optional_field) {
    case NSMEQUITIES_ORDERS_DISABLE_ORDER_ENTRY_RESPONSE_OPTIONAL_FIELD_USERREFIDX:
        return parse_nsmequities_orders_user_ref_idx(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string nsmequities_orders_enable_order_entry_response_optional_value_messages[] = {
    { NSMEQUITIES_ORDERS_ENABLE_ORDER_ENTRY_RESPONSE_OPTIONAL_FIELD_USERREFIDX, "User Ref Idx" },
    { 0, NULL }
};

/* Enable Order Entry Response Optional Value: dispatch on enable_order_entry_response_optional_field */
static unsigned
dissect_nsmequities_orders_enable_order_entry_response_optional_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t enable_order_entry_response_optional_field)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, enable_order_entry_response_optional_field, nsmequities_orders_enable_order_entry_response_optional_value_messages, "Unknown (%u)"));

    switch (enable_order_entry_response_optional_field) {
    case NSMEQUITIES_ORDERS_ENABLE_ORDER_ENTRY_RESPONSE_OPTIONAL_FIELD_USERREFIDX:
        return parse_nsmequities_orders_user_ref_idx(tvb, pinfo, tree, offset);
    }

    return offset;
}

/* Show preference of the dispatched message */
static bool
nsmequities_orders_client_packet_show(uint32_t client_packet_type)
{
    switch (client_packet_type) {
    case NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_DEBUG_PACKET:
        return nsmequities_orders_show_session_messages;
    case NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_LOGIN_REQUEST_PACKET:
        return nsmequities_orders_show_session_messages;
    case NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_UNSEQUENCED_DATA_PACKET:
        return nsmequities_orders_show_session_messages;
    }

    return true;
}

typedef struct nsmequities_orders_client_packet_parse nsmequities_orders_client_packet_parse;

struct nsmequities_orders_client_packet_parse {
    const value_string *messages;
    unsigned (*dissect)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t client_packet_type);
};

static const nsmequities_orders_client_packet_parse nsmequities_orders_client_packet_parse_v50 = { nsmequities_orders_client_packet_messages, dissect_nsmequities_orders_client_packet_client_payload };
static const nsmequities_orders_client_packet_parse nsmequities_orders_client_packet_parse_v422018 = { nsmequities_orders_client_packet_messages_v422018, dissect_nsmequities_orders_client_packet_client_payload_v422018 };

/* Parse tree of the selected version */
static const nsmequities_orders_client_packet_parse *
nsmequities_orders_client_packet_parse_for(int version)
{
    switch (version) {
    case NSMEQUITIES_ORDERS_VERSION_4_2_2018:
        return &nsmequities_orders_client_packet_parse_v422018;
    default:
        return &nsmequities_orders_client_packet_parse_v50;
    }
}

/* Show preference of the dispatched message */
static bool
nsmequities_orders_server_packet_show(uint32_t server_packet_type)
{
    switch (server_packet_type) {
    case NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_DEBUG_PACKET:
        return nsmequities_orders_show_session_messages;
    case NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET:
        return nsmequities_orders_show_session_messages;
    case NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET:
        return nsmequities_orders_show_session_messages;
    case NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET:
        return nsmequities_orders_show_session_messages;
    }

    return true;
}

typedef struct nsmequities_orders_server_packet_parse nsmequities_orders_server_packet_parse;

struct nsmequities_orders_server_packet_parse {
    const value_string *messages;
    unsigned (*dissect)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t server_packet_type);
};

static const nsmequities_orders_server_packet_parse nsmequities_orders_server_packet_parse_v50 = { nsmequities_orders_server_packet_messages, dissect_nsmequities_orders_server_packet_server_payload };
static const nsmequities_orders_server_packet_parse nsmequities_orders_server_packet_parse_v422018 = { nsmequities_orders_server_packet_messages_v422018, dissect_nsmequities_orders_server_packet_server_payload_v422018 };

/* Parse tree of the selected version */
static const nsmequities_orders_server_packet_parse *
nsmequities_orders_server_packet_parse_for(int version)
{
    switch (version) {
    case NSMEQUITIES_ORDERS_VERSION_4_2_2018:
        return &nsmequities_orders_server_packet_parse_v422018;
    default:
        return &nsmequities_orders_server_packet_parse_v50;
    }
}

/* Is the port the acceptor's, by preference or by the declared ports? */
static bool
nsmequities_orders_acceptor_port(uint32_t port)
{
    return port != 0 && (port == nsmequities_orders_pref_acceptor_port || port == 8001 || port == 8003);
}

/* Connection role of the frame's sender */
static int
nsmequities_orders_role(packet_info *pinfo)
{
    if (nsmequities_orders_pref_assume_role != NSMEQUITIES_ORDERS_ROLE_RESOLVE) {
        return nsmequities_orders_pref_assume_role;
    }

    if (nsmequities_orders_acceptor_port(pinfo->destport)) {
        return NSMEQUITIES_ORDERS_ROLE_INITIATOR;
    }

    if (nsmequities_orders_acceptor_port(pinfo->srcport)) {
        return NSMEQUITIES_ORDERS_ROLE_ACCEPTOR;
    }

    nsmequities_orders_conversation *session = nsmequities_orders_conversation_of(pinfo);

    bool first = pinfo->srcport == session->port
        && addresses_equal(&pinfo->src, &session->initiator);

    if (nsmequities_orders_pref_swap_sides) {
        first = !first;
    }

    if (session->swapped) {
        first = !first;
    }

    return first ? NSMEQUITIES_ORDERS_ROLE_INITIATOR : NSMEQUITIES_ORDERS_ROLE_ACCEPTOR;
}

/* Swap the resolved sides of the frame's conversation */
static void
nsmequities_orders_swap(packet_info *pinfo)
{
    nsmequities_orders_conversation *session = nsmequities_orders_conversation_of(pinfo);

    session->swapped = !session->swapped;
}

/* NsmEquities Orders message size adjusts the declared length */
#define NSMEQUITIES_ORDERS_CLIENT_PACKET_MESSAGE_ADJUSTMENT 2

/* One length prefixed message, returns the consumed size */
static unsigned
dissect_nsmequities_orders_client_packet_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, const nsmequities_orders_client_packet_parse *parse)
{
    uint32_t packet_length = tvb_get_ntohs(tvb, offset);
    uint32_t client_packet_type = tvb_get_uint8(tvb, offset + 2);

    const char *name = val_to_str(pinfo->pool, client_packet_type, parse->messages, "Unknown (%u)");

    proto_tree *message = nsmequities_orders_client_packet_show(client_packet_type)
        ? proto_tree_add_subtree_format(tree, tvb, offset, packet_length + NSMEQUITIES_ORDERS_CLIENT_PACKET_MESSAGE_ADJUSTMENT, ett_nsmequities_orders_message, NULL, "%s ('%c')", name, (char)client_packet_type)
        : tree;

    unsigned position = offset;

    position = dissect_nsmequities_orders_client_packet_header(tvb, pinfo, message, position);

    position = parse->dissect(tvb, pinfo, message, position, client_packet_type);

    /* The parsed fields must account for the declared length exactly */
    if (position != offset + packet_length + NSMEQUITIES_ORDERS_CLIENT_PACKET_MESSAGE_ADJUSTMENT) {
        expert_add_info(pinfo, message, &ei_nsmequities_orders_length);
    }

    return packet_length + NSMEQUITIES_ORDERS_CLIENT_PACKET_MESSAGE_ADJUSTMENT;
}

/* Framed messages to the end of the stream, a partial
   frame asks the transport for its remaining bytes */
static unsigned
dissect_nsmequities_orders_client_packet_messages(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, const nsmequities_orders_client_packet_parse *parse)
{
    while (offset < tvb_reported_length(tvb)) {
        unsigned remaining = tvb_reported_length(tvb) - offset;

        if (remaining < 2) {
            pinfo->desegment_offset = (int)offset;
            pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            return offset;
        }

        unsigned frame = tvb_get_ntohs(tvb, offset) + NSMEQUITIES_ORDERS_CLIENT_PACKET_MESSAGE_ADJUSTMENT;

        if (remaining < frame) {
            pinfo->desegment_offset = (int)offset;
            pinfo->desegment_len = frame - remaining;
            return offset;
        }

        offset += dissect_nsmequities_orders_client_packet_message(tvb, pinfo, tree, offset, parse);
    }

    return offset;
}

/* Client Packet: header then counted messages */
static int
dissect_nsmequities_orders_client_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, NSMEQUITIES_ORDERS_PROTOCOL_SHORT);
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *item = proto_tree_add_item(tree, proto_nsmequities_orders, tvb, 0, -1, ENC_NA);
    proto_tree *packet = proto_item_add_subtree(item, ett_nsmequities_orders);

    proto_item_append_text(item, ", Client");
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "Client");

    uint64_t seconds = (uint64_t)pinfo->abs_ts.secs;
    int version = nsmequities_orders_version(seconds);

    proto_item_append_text(item, " %s", nsmequities_orders_version_name(version));

    const nsmequities_orders_client_packet_parse *parse = nsmequities_orders_client_packet_parse_for(version);
    unsigned position = 0;

    position = dissect_nsmequities_orders_client_packet_messages(tvb, pinfo, packet, position, parse);

    return (int)position;
}

/* NsmEquities Orders message size adjusts the declared length */
#define NSMEQUITIES_ORDERS_SERVER_PACKET_MESSAGE_ADJUSTMENT 2

/* One length prefixed message, returns the consumed size */
static unsigned
dissect_nsmequities_orders_server_packet_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, const nsmequities_orders_server_packet_parse *parse)
{
    uint32_t packet_length = tvb_get_ntohs(tvb, offset);
    uint32_t server_packet_type = tvb_get_uint8(tvb, offset + 2);

    const char *name = val_to_str(pinfo->pool, server_packet_type, parse->messages, "Unknown (%u)");

    proto_tree *message = nsmequities_orders_server_packet_show(server_packet_type)
        ? proto_tree_add_subtree_format(tree, tvb, offset, packet_length + NSMEQUITIES_ORDERS_SERVER_PACKET_MESSAGE_ADJUSTMENT, ett_nsmequities_orders_message, NULL, "%s ('%c')", name, (char)server_packet_type)
        : tree;

    unsigned position = offset;

    position = dissect_nsmequities_orders_server_packet_header(tvb, pinfo, message, position);

    position = parse->dissect(tvb, pinfo, message, position, server_packet_type);

    /* The parsed fields must account for the declared length exactly */
    if (position != offset + packet_length + NSMEQUITIES_ORDERS_SERVER_PACKET_MESSAGE_ADJUSTMENT) {
        expert_add_info(pinfo, message, &ei_nsmequities_orders_length);
    }

    return packet_length + NSMEQUITIES_ORDERS_SERVER_PACKET_MESSAGE_ADJUSTMENT;
}

/* Framed messages to the end of the stream, a partial
   frame asks the transport for its remaining bytes */
static unsigned
dissect_nsmequities_orders_server_packet_messages(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, const nsmequities_orders_server_packet_parse *parse)
{
    while (offset < tvb_reported_length(tvb)) {
        unsigned remaining = tvb_reported_length(tvb) - offset;

        if (remaining < 2) {
            pinfo->desegment_offset = (int)offset;
            pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            return offset;
        }

        unsigned frame = tvb_get_ntohs(tvb, offset) + NSMEQUITIES_ORDERS_SERVER_PACKET_MESSAGE_ADJUSTMENT;

        if (remaining < frame) {
            pinfo->desegment_offset = (int)offset;
            pinfo->desegment_len = frame - remaining;
            return offset;
        }

        offset += dissect_nsmequities_orders_server_packet_message(tvb, pinfo, tree, offset, parse);
    }

    return offset;
}

/* Server Packet: header then counted messages */
static int
dissect_nsmequities_orders_server_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, NSMEQUITIES_ORDERS_PROTOCOL_SHORT);
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *item = proto_tree_add_item(tree, proto_nsmequities_orders, tvb, 0, -1, ENC_NA);
    proto_tree *packet = proto_item_add_subtree(item, ett_nsmequities_orders);

    proto_item_append_text(item, ", Server");
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "Server");

    uint64_t seconds = (uint64_t)pinfo->abs_ts.secs;
    int version = nsmequities_orders_version(seconds);

    proto_item_append_text(item, " %s", nsmequities_orders_version_name(version));

    const nsmequities_orders_server_packet_parse *parse = nsmequities_orders_server_packet_parse_for(version);
    unsigned position = 0;

    position = dissect_nsmequities_orders_server_packet_messages(tvb, pinfo, packet, position, parse);

    return (int)position;
}

static bool nsmequities_orders_client_packet_heur_fingerprint(tvbuff_t *tvb);
static bool nsmequities_orders_server_packet_heur_fingerprint(tvbuff_t *tvb);

/* Packet: the side of the transport and the sender's connection role */
static int
dissect_nsmequities_orders(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (nsmequities_orders_role(pinfo) == NSMEQUITIES_ORDERS_ROLE_INITIATOR) {
        if (!nsmequities_orders_client_packet_heur_fingerprint(tvb) && nsmequities_orders_server_packet_heur_fingerprint(tvb)) {
            nsmequities_orders_swap(pinfo);

            return dissect_nsmequities_orders_server_packet(tvb, pinfo, tree, data);
        }

        return dissect_nsmequities_orders_client_packet(tvb, pinfo, tree, data);
    }

    if (!nsmequities_orders_server_packet_heur_fingerprint(tvb) && nsmequities_orders_client_packet_heur_fingerprint(tvb)) {
        nsmequities_orders_swap(pinfo);

        return dissect_nsmequities_orders_client_packet(tvb, pinfo, tree, data);
    }

    return dissect_nsmequities_orders_server_packet(tvb, pinfo, tree, data);
}

/* The fewest bytes any frame of the protocol holds, a header without messages */
#define NSMEQUITIES_ORDERS_MINIMUM_SIZE 3

/* The frame travels on a port the feed is assigned, the ports are the
   deployment's and held by preference */
static bool
nsmequities_orders_heur_port(packet_info *pinfo)
{
    return value_is_in_range(nsmequities_orders_pref_ports, pinfo->destport)
        || value_is_in_range(nsmequities_orders_pref_ports, pinfo->srcport);
}

/* The first frame's declared length fits the stream */
static bool
nsmequities_orders_client_packet_heur_frame(tvbuff_t *tvb)
{
    int frame = (int)(tvb_get_ntohs(tvb, 0) + NSMEQUITIES_ORDERS_CLIENT_PACKET_MESSAGE_ADJUSTMENT);

    return frame >= NSMEQUITIES_ORDERS_CLIENT_PACKET_HEADER_SIZE && frame <= (int)tvb_reported_length(tvb);
}

/* Fingerprint of Client Packet: would its message dispatch accept the frame? */
static bool
nsmequities_orders_client_packet_heur_fingerprint(tvbuff_t *tvb)
{
    if (tvb_captured_length(tvb) < 3) {
        return false;
    }

    uint32_t client_packet_type = tvb_get_uint8(tvb, 2);

    switch (client_packet_type) {
    case NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_DEBUG_PACKET: /* Debug Packet */
    case NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_LOGIN_REQUEST_PACKET: /* Login Request Packet */
    case NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_UNSEQUENCED_DATA_PACKET: /* Unsequenced Data Packet */
    case NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_CLIENT_HEARTBEAT_PACKET: /* Client Heartbeat */
    case NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_LOGOUT_REQUEST_PACKET: /* Logout Request */
        return true;
    }

    return false;
}

/* Does the frame pass every test of Client Packet? */
static bool
nsmequities_orders_client_packet_heur_accepts(tvbuff_t *tvb, packet_info *pinfo)
{
    if (!nsmequities_orders_heur_port(pinfo)) {
        return false;
    }

    if (!nsmequities_orders_client_packet_heur_frame(tvb)) {
        return false;
    }

    if (!nsmequities_orders_client_packet_heur_fingerprint(tvb)) {
        return false;
    }

    return true;
}

/* The first frame's declared length fits the stream */
static bool
nsmequities_orders_server_packet_heur_frame(tvbuff_t *tvb)
{
    int frame = (int)(tvb_get_ntohs(tvb, 0) + NSMEQUITIES_ORDERS_SERVER_PACKET_MESSAGE_ADJUSTMENT);

    return frame >= NSMEQUITIES_ORDERS_SERVER_PACKET_HEADER_SIZE && frame <= (int)tvb_reported_length(tvb);
}

/* Fingerprint of Server Packet: would its message dispatch accept the frame? */
static bool
nsmequities_orders_server_packet_heur_fingerprint(tvbuff_t *tvb)
{
    if (tvb_captured_length(tvb) < 3) {
        return false;
    }

    uint32_t server_packet_type = tvb_get_uint8(tvb, 2);

    switch (server_packet_type) {
    case NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_DEBUG_PACKET: /* Debug Packet */
    case NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_LOGIN_ACCEPTED_PACKET: /* Login Accepted Packet */
    case NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_LOGIN_REJECTED_PACKET: /* Login Rejected Packet */
    case NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_SEQUENCED_DATA_PACKET: /* Sequenced Data Packet */
    case NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_SERVER_HEARTBEAT_PACKET: /* Server Heartbeat */
    case NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_END_OF_SESSION_PACKET: /* End Of Session */
        return true;
    }

    return false;
}

/* Does the frame pass every test of Server Packet? */
static bool
nsmequities_orders_server_packet_heur_accepts(tvbuff_t *tvb, packet_info *pinfo)
{
    if (!nsmequities_orders_heur_port(pinfo)) {
        return false;
    }

    if (!nsmequities_orders_server_packet_heur_frame(tvb)) {
        return false;
    }

    if (!nsmequities_orders_server_packet_heur_fingerprint(tvb)) {
        return false;
    }

    return true;
}

/* Recognize the protocol by the port it travels on, by the side of the sender's
   connection role, the other side may have sent the conversation's first frame */
static bool
dissect_nsmequities_orders_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (tvb_captured_length(tvb) < NSMEQUITIES_ORDERS_MINIMUM_SIZE) {
        return false;
    }

    bool (*first)(tvbuff_t *, packet_info *) = nsmequities_orders_client_packet_heur_accepts;
    bool (*second)(tvbuff_t *, packet_info *) = nsmequities_orders_server_packet_heur_accepts;

    if (nsmequities_orders_role(pinfo) == NSMEQUITIES_ORDERS_ROLE_ACCEPTOR) {
        first = second;
        second = nsmequities_orders_client_packet_heur_accepts;
    }

    if (first(tvb, pinfo)) {
        dissect_nsmequities_orders(tvb, pinfo, tree, data);
        return true;
    }

    nsmequities_orders_swap(pinfo);

    if (second(tvb, pinfo)) {
        dissect_nsmequities_orders(tvb, pinfo, tree, data);
        return true;
    }

    nsmequities_orders_swap(pinfo);

    return false;
}

/*
 * NsmEquities Orders Registration
 */

void
proto_register_nsmequities_orders(void)
{
    static hf_register_info hf[] = {

        /* Fields */
        { &hf_nsmequities_orders_accepted_sequence_number,
            { NSMEQUITIES_ORDERS_ACCEPTED_SEQUENCE_NUMBER_NAME,
              NSMEQUITIES_ORDERS_ACCEPTED_SEQUENCE_NUMBER_FILTER,
              NSMEQUITIES_ORDERS_ACCEPTED_SEQUENCE_NUMBER_TYPE,
              NSMEQUITIES_ORDERS_ACCEPTED_SEQUENCE_NUMBER_DISPLAY,
              NULL,
              NSMEQUITIES_ORDERS_ACCEPTED_SEQUENCE_NUMBER_MASK,
              NSMEQUITIES_ORDERS_ACCEPTED_SEQUENCE_NUMBER_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_accepted_session,
            { NSMEQUITIES_ORDERS_ACCEPTED_SESSION_NAME,
              NSMEQUITIES_ORDERS_ACCEPTED_SESSION_FILTER,
              NSMEQUITIES_ORDERS_ACCEPTED_SESSION_TYPE,
              NSMEQUITIES_ORDERS_ACCEPTED_SESSION_DISPLAY,
              NULL,
              NSMEQUITIES_ORDERS_ACCEPTED_SESSION_MASK,
              NSMEQUITIES_ORDERS_ACCEPTED_SESSION_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_account_query_optional_field,
            { NSMEQUITIES_ORDERS_ACCOUNT_QUERY_OPTIONAL_FIELD_NAME,
              NSMEQUITIES_ORDERS_ACCOUNT_QUERY_OPTIONAL_FIELD_FILTER,
              NSMEQUITIES_ORDERS_ACCOUNT_QUERY_OPTIONAL_FIELD_TYPE,
              NSMEQUITIES_ORDERS_ACCOUNT_QUERY_OPTIONAL_FIELD_DISPLAY,
              VALS(nsmequities_orders_account_query_optional_field_vals),
              NSMEQUITIES_ORDERS_ACCOUNT_QUERY_OPTIONAL_FIELD_MASK,
              NSMEQUITIES_ORDERS_ACCOUNT_QUERY_OPTIONAL_FIELD_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_account_query_response_optional_field,
            { NSMEQUITIES_ORDERS_ACCOUNT_QUERY_RESPONSE_OPTIONAL_FIELD_NAME,
              NSMEQUITIES_ORDERS_ACCOUNT_QUERY_RESPONSE_OPTIONAL_FIELD_FILTER,
              NSMEQUITIES_ORDERS_ACCOUNT_QUERY_RESPONSE_OPTIONAL_FIELD_TYPE,
              NSMEQUITIES_ORDERS_ACCOUNT_QUERY_RESPONSE_OPTIONAL_FIELD_DISPLAY,
              VALS(nsmequities_orders_account_query_response_optional_field_vals),
              NSMEQUITIES_ORDERS_ACCOUNT_QUERY_RESPONSE_OPTIONAL_FIELD_MASK,
              NSMEQUITIES_ORDERS_ACCOUNT_QUERY_RESPONSE_OPTIONAL_FIELD_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_aiq_canceled_optional_field,
            { NSMEQUITIES_ORDERS_AIQ_CANCELED_OPTIONAL_FIELD_NAME,
              NSMEQUITIES_ORDERS_AIQ_CANCELED_OPTIONAL_FIELD_FILTER,
              NSMEQUITIES_ORDERS_AIQ_CANCELED_OPTIONAL_FIELD_TYPE,
              NSMEQUITIES_ORDERS_AIQ_CANCELED_OPTIONAL_FIELD_DISPLAY,
              VALS(nsmequities_orders_aiq_canceled_optional_field_vals),
              NSMEQUITIES_ORDERS_AIQ_CANCELED_OPTIONAL_FIELD_MASK,
              NSMEQUITIES_ORDERS_AIQ_CANCELED_OPTIONAL_FIELD_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_aiq_group_id,
            { NSMEQUITIES_ORDERS_AIQ_GROUP_ID_NAME,
              NSMEQUITIES_ORDERS_AIQ_GROUP_ID_FILTER,
              NSMEQUITIES_ORDERS_AIQ_GROUP_ID_TYPE,
              NSMEQUITIES_ORDERS_AIQ_GROUP_ID_DISPLAY,
              NULL,
              NSMEQUITIES_ORDERS_AIQ_GROUP_ID_MASK,
              NSMEQUITIES_ORDERS_AIQ_GROUP_ID_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_aiq_strategy,
            { NSMEQUITIES_ORDERS_AIQ_STRATEGY_NAME,
              NSMEQUITIES_ORDERS_AIQ_STRATEGY_FILTER,
              NSMEQUITIES_ORDERS_AIQ_STRATEGY_TYPE,
              NSMEQUITIES_ORDERS_AIQ_STRATEGY_DISPLAY,
              VALS(nsmequities_orders_aiq_strategy_vals),
              NSMEQUITIES_ORDERS_AIQ_STRATEGY_MASK,
              NSMEQUITIES_ORDERS_AIQ_STRATEGY_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_appendage_length,
            { NSMEQUITIES_ORDERS_APPENDAGE_LENGTH_NAME,
              NSMEQUITIES_ORDERS_APPENDAGE_LENGTH_FILTER,
              NSMEQUITIES_ORDERS_APPENDAGE_LENGTH_TYPE,
              NSMEQUITIES_ORDERS_APPENDAGE_LENGTH_DISPLAY,
              NULL,
              NSMEQUITIES_ORDERS_APPENDAGE_LENGTH_MASK,
              NSMEQUITIES_ORDERS_APPENDAGE_LENGTH_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_appendage_length_v50,
            { NSMEQUITIES_ORDERS_APPENDAGE_LENGTH_V50_NAME,
              NSMEQUITIES_ORDERS_APPENDAGE_LENGTH_V50_FILTER,
              NSMEQUITIES_ORDERS_APPENDAGE_LENGTH_V50_TYPE,
              NSMEQUITIES_ORDERS_APPENDAGE_LENGTH_V50_DISPLAY,
              NULL,
              NSMEQUITIES_ORDERS_APPENDAGE_LENGTH_V50_MASK,
              NSMEQUITIES_ORDERS_APPENDAGE_LENGTH_V50_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_bbo_weight_indicator,
            { NSMEQUITIES_ORDERS_BBO_WEIGHT_INDICATOR_NAME,
              NSMEQUITIES_ORDERS_BBO_WEIGHT_INDICATOR_FILTER,
              NSMEQUITIES_ORDERS_BBO_WEIGHT_INDICATOR_TYPE,
              NSMEQUITIES_ORDERS_BBO_WEIGHT_INDICATOR_DISPLAY,
              VALS(nsmequities_orders_bbo_weight_indicator_vals),
              NSMEQUITIES_ORDERS_BBO_WEIGHT_INDICATOR_MASK,
              NULL,
              HFILL } },
        { &hf_nsmequities_orders_broken_trade_optional_field,
            { NSMEQUITIES_ORDERS_BROKEN_TRADE_OPTIONAL_FIELD_NAME,
              NSMEQUITIES_ORDERS_BROKEN_TRADE_OPTIONAL_FIELD_FILTER,
              NSMEQUITIES_ORDERS_BROKEN_TRADE_OPTIONAL_FIELD_TYPE,
              NSMEQUITIES_ORDERS_BROKEN_TRADE_OPTIONAL_FIELD_DISPLAY,
              VALS(nsmequities_orders_broken_trade_optional_field_vals),
              NSMEQUITIES_ORDERS_BROKEN_TRADE_OPTIONAL_FIELD_MASK,
              NSMEQUITIES_ORDERS_BROKEN_TRADE_OPTIONAL_FIELD_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_broken_trade_reason,
            { NSMEQUITIES_ORDERS_BROKEN_TRADE_REASON_NAME,
              NSMEQUITIES_ORDERS_BROKEN_TRADE_REASON_FILTER,
              NSMEQUITIES_ORDERS_BROKEN_TRADE_REASON_TYPE,
              NSMEQUITIES_ORDERS_BROKEN_TRADE_REASON_DISPLAY,
              VALS(nsmequities_orders_broken_trade_reason_vals),
              NSMEQUITIES_ORDERS_BROKEN_TRADE_REASON_MASK,
              NSMEQUITIES_ORDERS_BROKEN_TRADE_REASON_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_buy_sell_indicator,
            { NSMEQUITIES_ORDERS_BUY_SELL_INDICATOR_NAME,
              NSMEQUITIES_ORDERS_BUY_SELL_INDICATOR_FILTER,
              NSMEQUITIES_ORDERS_BUY_SELL_INDICATOR_TYPE,
              NSMEQUITIES_ORDERS_BUY_SELL_INDICATOR_DISPLAY,
              VALS(nsmequities_orders_buy_sell_indicator_vals),
              NSMEQUITIES_ORDERS_BUY_SELL_INDICATOR_MASK,
              NULL,
              HFILL } },
        { &hf_nsmequities_orders_cancel_order_optional_field,
            { NSMEQUITIES_ORDERS_CANCEL_ORDER_OPTIONAL_FIELD_NAME,
              NSMEQUITIES_ORDERS_CANCEL_ORDER_OPTIONAL_FIELD_FILTER,
              NSMEQUITIES_ORDERS_CANCEL_ORDER_OPTIONAL_FIELD_TYPE,
              NSMEQUITIES_ORDERS_CANCEL_ORDER_OPTIONAL_FIELD_DISPLAY,
              VALS(nsmequities_orders_cancel_order_optional_field_vals),
              NSMEQUITIES_ORDERS_CANCEL_ORDER_OPTIONAL_FIELD_MASK,
              NSMEQUITIES_ORDERS_CANCEL_ORDER_OPTIONAL_FIELD_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_cancel_order_reason,
            { NSMEQUITIES_ORDERS_CANCEL_ORDER_REASON_NAME,
              NSMEQUITIES_ORDERS_CANCEL_ORDER_REASON_FILTER,
              NSMEQUITIES_ORDERS_CANCEL_ORDER_REASON_TYPE,
              NSMEQUITIES_ORDERS_CANCEL_ORDER_REASON_DISPLAY,
              VALS(nsmequities_orders_cancel_order_reason_vals),
              NSMEQUITIES_ORDERS_CANCEL_ORDER_REASON_MASK,
              NSMEQUITIES_ORDERS_CANCEL_ORDER_REASON_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_cancel_pending_optional_field,
            { NSMEQUITIES_ORDERS_CANCEL_PENDING_OPTIONAL_FIELD_NAME,
              NSMEQUITIES_ORDERS_CANCEL_PENDING_OPTIONAL_FIELD_FILTER,
              NSMEQUITIES_ORDERS_CANCEL_PENDING_OPTIONAL_FIELD_TYPE,
              NSMEQUITIES_ORDERS_CANCEL_PENDING_OPTIONAL_FIELD_DISPLAY,
              VALS(nsmequities_orders_cancel_pending_optional_field_vals),
              NSMEQUITIES_ORDERS_CANCEL_PENDING_OPTIONAL_FIELD_MASK,
              NSMEQUITIES_ORDERS_CANCEL_PENDING_OPTIONAL_FIELD_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_cancel_reject_optional_field,
            { NSMEQUITIES_ORDERS_CANCEL_REJECT_OPTIONAL_FIELD_NAME,
              NSMEQUITIES_ORDERS_CANCEL_REJECT_OPTIONAL_FIELD_FILTER,
              NSMEQUITIES_ORDERS_CANCEL_REJECT_OPTIONAL_FIELD_TYPE,
              NSMEQUITIES_ORDERS_CANCEL_REJECT_OPTIONAL_FIELD_DISPLAY,
              VALS(nsmequities_orders_cancel_reject_optional_field_vals),
              NSMEQUITIES_ORDERS_CANCEL_REJECT_OPTIONAL_FIELD_MASK,
              NSMEQUITIES_ORDERS_CANCEL_REJECT_OPTIONAL_FIELD_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_canceled_message_optional_field,
            { NSMEQUITIES_ORDERS_CANCELED_MESSAGE_OPTIONAL_FIELD_NAME,
              NSMEQUITIES_ORDERS_CANCELED_MESSAGE_OPTIONAL_FIELD_FILTER,
              NSMEQUITIES_ORDERS_CANCELED_MESSAGE_OPTIONAL_FIELD_TYPE,
              NSMEQUITIES_ORDERS_CANCELED_MESSAGE_OPTIONAL_FIELD_DISPLAY,
              VALS(nsmequities_orders_canceled_message_optional_field_vals),
              NSMEQUITIES_ORDERS_CANCELED_MESSAGE_OPTIONAL_FIELD_MASK,
              NSMEQUITIES_ORDERS_CANCELED_MESSAGE_OPTIONAL_FIELD_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_capacity,
            { NSMEQUITIES_ORDERS_CAPACITY_NAME,
              NSMEQUITIES_ORDERS_CAPACITY_FILTER,
              NSMEQUITIES_ORDERS_CAPACITY_TYPE,
              NSMEQUITIES_ORDERS_CAPACITY_DISPLAY,
              VALS(nsmequities_orders_capacity_vals),
              NSMEQUITIES_ORDERS_CAPACITY_MASK,
              NULL,
              HFILL } },
        { &hf_nsmequities_orders_clordid,
            { NSMEQUITIES_ORDERS_CLORDID_NAME,
              NSMEQUITIES_ORDERS_CLORDID_FILTER,
              NSMEQUITIES_ORDERS_CLORDID_TYPE,
              NSMEQUITIES_ORDERS_CLORDID_DISPLAY,
              NULL,
              NSMEQUITIES_ORDERS_CLORDID_MASK,
              NSMEQUITIES_ORDERS_CLORDID_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_client_packet_type,
            { NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_NAME,
              NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_FILTER,
              NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_TYPE,
              NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_DISPLAY,
              VALS(nsmequities_orders_client_packet_type_vals),
              NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_MASK,
              NSMEQUITIES_ORDERS_CLIENT_PACKET_TYPE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_cross_type,
            { NSMEQUITIES_ORDERS_CROSS_TYPE_NAME,
              NSMEQUITIES_ORDERS_CROSS_TYPE_FILTER,
              NSMEQUITIES_ORDERS_CROSS_TYPE_TYPE,
              NSMEQUITIES_ORDERS_CROSS_TYPE_DISPLAY,
              VALS(nsmequities_orders_cross_type_vals),
              NSMEQUITIES_ORDERS_CROSS_TYPE_MASK,
              NSMEQUITIES_ORDERS_CROSS_TYPE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_customer_type,
            { NSMEQUITIES_ORDERS_CUSTOMER_TYPE_NAME,
              NSMEQUITIES_ORDERS_CUSTOMER_TYPE_FILTER,
              NSMEQUITIES_ORDERS_CUSTOMER_TYPE_TYPE,
              NSMEQUITIES_ORDERS_CUSTOMER_TYPE_DISPLAY,
              VALS(nsmequities_orders_customer_type_vals),
              NSMEQUITIES_ORDERS_CUSTOMER_TYPE_MASK,
              NSMEQUITIES_ORDERS_CUSTOMER_TYPE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_customer_type_v422018,
            { NSMEQUITIES_ORDERS_CUSTOMER_TYPE_V422018_NAME,
              NSMEQUITIES_ORDERS_CUSTOMER_TYPE_V422018_FILTER,
              NSMEQUITIES_ORDERS_CUSTOMER_TYPE_V422018_TYPE,
              NSMEQUITIES_ORDERS_CUSTOMER_TYPE_V422018_DISPLAY,
              VALS(nsmequities_orders_customer_type_v422018_vals),
              NSMEQUITIES_ORDERS_CUSTOMER_TYPE_V422018_MASK,
              NSMEQUITIES_ORDERS_CUSTOMER_TYPE_V422018_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_debug_text,
            { NSMEQUITIES_ORDERS_DEBUG_TEXT_NAME,
              NSMEQUITIES_ORDERS_DEBUG_TEXT_FILTER,
              NSMEQUITIES_ORDERS_DEBUG_TEXT_TYPE,
              NSMEQUITIES_ORDERS_DEBUG_TEXT_DISPLAY,
              NULL,
              NSMEQUITIES_ORDERS_DEBUG_TEXT_MASK,
              NSMEQUITIES_ORDERS_DEBUG_TEXT_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_decrement_shares,
            { NSMEQUITIES_ORDERS_DECREMENT_SHARES_NAME,
              NSMEQUITIES_ORDERS_DECREMENT_SHARES_FILTER,
              NSMEQUITIES_ORDERS_DECREMENT_SHARES_TYPE,
              NSMEQUITIES_ORDERS_DECREMENT_SHARES_DISPLAY,
              NULL,
              NSMEQUITIES_ORDERS_DECREMENT_SHARES_MASK,
              NSMEQUITIES_ORDERS_DECREMENT_SHARES_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_disable_order_entry_request_optional_field,
            { NSMEQUITIES_ORDERS_DISABLE_ORDER_ENTRY_REQUEST_OPTIONAL_FIELD_NAME,
              NSMEQUITIES_ORDERS_DISABLE_ORDER_ENTRY_REQUEST_OPTIONAL_FIELD_FILTER,
              NSMEQUITIES_ORDERS_DISABLE_ORDER_ENTRY_REQUEST_OPTIONAL_FIELD_TYPE,
              NSMEQUITIES_ORDERS_DISABLE_ORDER_ENTRY_REQUEST_OPTIONAL_FIELD_DISPLAY,
              VALS(nsmequities_orders_disable_order_entry_request_optional_field_vals),
              NSMEQUITIES_ORDERS_DISABLE_ORDER_ENTRY_REQUEST_OPTIONAL_FIELD_MASK,
              NSMEQUITIES_ORDERS_DISABLE_ORDER_ENTRY_REQUEST_OPTIONAL_FIELD_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_disable_order_entry_response_optional_field,
            { NSMEQUITIES_ORDERS_DISABLE_ORDER_ENTRY_RESPONSE_OPTIONAL_FIELD_NAME,
              NSMEQUITIES_ORDERS_DISABLE_ORDER_ENTRY_RESPONSE_OPTIONAL_FIELD_FILTER,
              NSMEQUITIES_ORDERS_DISABLE_ORDER_ENTRY_RESPONSE_OPTIONAL_FIELD_TYPE,
              NSMEQUITIES_ORDERS_DISABLE_ORDER_ENTRY_RESPONSE_OPTIONAL_FIELD_DISPLAY,
              VALS(nsmequities_orders_disable_order_entry_response_optional_field_vals),
              NSMEQUITIES_ORDERS_DISABLE_ORDER_ENTRY_RESPONSE_OPTIONAL_FIELD_MASK,
              NSMEQUITIES_ORDERS_DISABLE_ORDER_ENTRY_RESPONSE_OPTIONAL_FIELD_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_discretion_peg_offset,
            { NSMEQUITIES_ORDERS_DISCRETION_PEG_OFFSET_NAME,
              NSMEQUITIES_ORDERS_DISCRETION_PEG_OFFSET_FILTER,
              NSMEQUITIES_ORDERS_DISCRETION_PEG_OFFSET_TYPE,
              NSMEQUITIES_ORDERS_DISCRETION_PEG_OFFSET_DISPLAY,
              CF_FUNC(nsmequities_orders_format_decimal_4_32),
              NSMEQUITIES_ORDERS_DISCRETION_PEG_OFFSET_MASK,
              NSMEQUITIES_ORDERS_DISCRETION_PEG_OFFSET_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_discretion_price,
            { NSMEQUITIES_ORDERS_DISCRETION_PRICE_NAME,
              NSMEQUITIES_ORDERS_DISCRETION_PRICE_FILTER,
              NSMEQUITIES_ORDERS_DISCRETION_PRICE_TYPE,
              NSMEQUITIES_ORDERS_DISCRETION_PRICE_DISPLAY,
              CF_FUNC(nsmequities_orders_format_decimal_4_64_unsigned),
              NSMEQUITIES_ORDERS_DISCRETION_PRICE_MASK,
              NSMEQUITIES_ORDERS_DISCRETION_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_discretion_price_type,
            { NSMEQUITIES_ORDERS_DISCRETION_PRICE_TYPE_NAME,
              NSMEQUITIES_ORDERS_DISCRETION_PRICE_TYPE_FILTER,
              NSMEQUITIES_ORDERS_DISCRETION_PRICE_TYPE_TYPE,
              NSMEQUITIES_ORDERS_DISCRETION_PRICE_TYPE_DISPLAY,
              VALS(nsmequities_orders_discretion_price_type_vals),
              NSMEQUITIES_ORDERS_DISCRETION_PRICE_TYPE_MASK,
              NSMEQUITIES_ORDERS_DISCRETION_PRICE_TYPE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_display,
            { NSMEQUITIES_ORDERS_DISPLAY_NAME,
              NSMEQUITIES_ORDERS_DISPLAY_FILTER,
              NSMEQUITIES_ORDERS_DISPLAY_TYPE,
              NSMEQUITIES_ORDERS_DISPLAY_DISPLAY,
              VALS(nsmequities_orders_display_vals),
              NSMEQUITIES_ORDERS_DISPLAY_MASK,
              NULL,
              HFILL } },
        { &hf_nsmequities_orders_display_price,
            { NSMEQUITIES_ORDERS_DISPLAY_PRICE_NAME,
              NSMEQUITIES_ORDERS_DISPLAY_PRICE_FILTER,
              NSMEQUITIES_ORDERS_DISPLAY_PRICE_TYPE,
              NSMEQUITIES_ORDERS_DISPLAY_PRICE_DISPLAY,
              CF_FUNC(nsmequities_orders_format_decimal_4_64_unsigned),
              NSMEQUITIES_ORDERS_DISPLAY_PRICE_MASK,
              NSMEQUITIES_ORDERS_DISPLAY_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_display_quantity,
            { NSMEQUITIES_ORDERS_DISPLAY_QUANTITY_NAME,
              NSMEQUITIES_ORDERS_DISPLAY_QUANTITY_FILTER,
              NSMEQUITIES_ORDERS_DISPLAY_QUANTITY_TYPE,
              NSMEQUITIES_ORDERS_DISPLAY_QUANTITY_DISPLAY,
              NULL,
              NSMEQUITIES_ORDERS_DISPLAY_QUANTITY_MASK,
              NSMEQUITIES_ORDERS_DISPLAY_QUANTITY_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_enable_order_entry_request_optional_field,
            { NSMEQUITIES_ORDERS_ENABLE_ORDER_ENTRY_REQUEST_OPTIONAL_FIELD_NAME,
              NSMEQUITIES_ORDERS_ENABLE_ORDER_ENTRY_REQUEST_OPTIONAL_FIELD_FILTER,
              NSMEQUITIES_ORDERS_ENABLE_ORDER_ENTRY_REQUEST_OPTIONAL_FIELD_TYPE,
              NSMEQUITIES_ORDERS_ENABLE_ORDER_ENTRY_REQUEST_OPTIONAL_FIELD_DISPLAY,
              VALS(nsmequities_orders_enable_order_entry_request_optional_field_vals),
              NSMEQUITIES_ORDERS_ENABLE_ORDER_ENTRY_REQUEST_OPTIONAL_FIELD_MASK,
              NSMEQUITIES_ORDERS_ENABLE_ORDER_ENTRY_REQUEST_OPTIONAL_FIELD_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_enable_order_entry_response_optional_field,
            { NSMEQUITIES_ORDERS_ENABLE_ORDER_ENTRY_RESPONSE_OPTIONAL_FIELD_NAME,
              NSMEQUITIES_ORDERS_ENABLE_ORDER_ENTRY_RESPONSE_OPTIONAL_FIELD_FILTER,
              NSMEQUITIES_ORDERS_ENABLE_ORDER_ENTRY_RESPONSE_OPTIONAL_FIELD_TYPE,
              NSMEQUITIES_ORDERS_ENABLE_ORDER_ENTRY_RESPONSE_OPTIONAL_FIELD_DISPLAY,
              VALS(nsmequities_orders_enable_order_entry_response_optional_field_vals),
              NSMEQUITIES_ORDERS_ENABLE_ORDER_ENTRY_RESPONSE_OPTIONAL_FIELD_MASK,
              NSMEQUITIES_ORDERS_ENABLE_ORDER_ENTRY_RESPONSE_OPTIONAL_FIELD_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_enter_order_optional_field,
            { NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_NAME,
              NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_FILTER,
              NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_TYPE,
              NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_DISPLAY,
              VALS(nsmequities_orders_enter_order_optional_field_vals),
              NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_MASK,
              NSMEQUITIES_ORDERS_ENTER_ORDER_OPTIONAL_FIELD_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_event_code,
            { NSMEQUITIES_ORDERS_EVENT_CODE_NAME,
              NSMEQUITIES_ORDERS_EVENT_CODE_FILTER,
              NSMEQUITIES_ORDERS_EVENT_CODE_TYPE,
              NSMEQUITIES_ORDERS_EVENT_CODE_DISPLAY,
              VALS(nsmequities_orders_event_code_vals),
              NSMEQUITIES_ORDERS_EVENT_CODE_MASK,
              NULL,
              HFILL } },
        { &hf_nsmequities_orders_executed_shares,
            { NSMEQUITIES_ORDERS_EXECUTED_SHARES_NAME,
              NSMEQUITIES_ORDERS_EXECUTED_SHARES_FILTER,
              NSMEQUITIES_ORDERS_EXECUTED_SHARES_TYPE,
              NSMEQUITIES_ORDERS_EXECUTED_SHARES_DISPLAY,
              NULL,
              NSMEQUITIES_ORDERS_EXECUTED_SHARES_MASK,
              NSMEQUITIES_ORDERS_EXECUTED_SHARES_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_execution_price,
            { NSMEQUITIES_ORDERS_EXECUTION_PRICE_NAME,
              NSMEQUITIES_ORDERS_EXECUTION_PRICE_FILTER,
              NSMEQUITIES_ORDERS_EXECUTION_PRICE_TYPE,
              NSMEQUITIES_ORDERS_EXECUTION_PRICE_DISPLAY,
              CF_FUNC(nsmequities_orders_format_decimal_4_64_unsigned),
              NSMEQUITIES_ORDERS_EXECUTION_PRICE_MASK,
              NSMEQUITIES_ORDERS_EXECUTION_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_execution_price_v422018,
            { NSMEQUITIES_ORDERS_EXECUTION_PRICE_V422018_NAME,
              NSMEQUITIES_ORDERS_EXECUTION_PRICE_V422018_FILTER,
              NSMEQUITIES_ORDERS_EXECUTION_PRICE_V422018_TYPE,
              NSMEQUITIES_ORDERS_EXECUTION_PRICE_V422018_DISPLAY,
              CF_FUNC(nsmequities_orders_format_decimal_4_32_unsigned),
              NSMEQUITIES_ORDERS_EXECUTION_PRICE_V422018_MASK,
              NSMEQUITIES_ORDERS_EXECUTION_PRICE_V422018_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_existing_order_token,
            { NSMEQUITIES_ORDERS_EXISTING_ORDER_TOKEN_NAME,
              NSMEQUITIES_ORDERS_EXISTING_ORDER_TOKEN_FILTER,
              NSMEQUITIES_ORDERS_EXISTING_ORDER_TOKEN_TYPE,
              NSMEQUITIES_ORDERS_EXISTING_ORDER_TOKEN_DISPLAY,
              NULL,
              NSMEQUITIES_ORDERS_EXISTING_ORDER_TOKEN_MASK,
              NSMEQUITIES_ORDERS_EXISTING_ORDER_TOKEN_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_expire_time,
            { NSMEQUITIES_ORDERS_EXPIRE_TIME_NAME,
              NSMEQUITIES_ORDERS_EXPIRE_TIME_FILTER,
              NSMEQUITIES_ORDERS_EXPIRE_TIME_TYPE,
              NSMEQUITIES_ORDERS_EXPIRE_TIME_DISPLAY,
              NULL,
              NSMEQUITIES_ORDERS_EXPIRE_TIME_MASK,
              NSMEQUITIES_ORDERS_EXPIRE_TIME_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_firm,
            { NSMEQUITIES_ORDERS_FIRM_NAME,
              NSMEQUITIES_ORDERS_FIRM_FILTER,
              NSMEQUITIES_ORDERS_FIRM_TYPE,
              NSMEQUITIES_ORDERS_FIRM_DISPLAY,
              NULL,
              NSMEQUITIES_ORDERS_FIRM_MASK,
              NSMEQUITIES_ORDERS_FIRM_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_group_id,
            { NSMEQUITIES_ORDERS_GROUP_ID_NAME,
              NSMEQUITIES_ORDERS_GROUP_ID_FILTER,
              NSMEQUITIES_ORDERS_GROUP_ID_TYPE,
              NSMEQUITIES_ORDERS_GROUP_ID_DISPLAY,
              NULL,
              NSMEQUITIES_ORDERS_GROUP_ID_MASK,
              NSMEQUITIES_ORDERS_GROUP_ID_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_handle_inst,
            { NSMEQUITIES_ORDERS_HANDLE_INST_NAME,
              NSMEQUITIES_ORDERS_HANDLE_INST_FILTER,
              NSMEQUITIES_ORDERS_HANDLE_INST_TYPE,
              NSMEQUITIES_ORDERS_HANDLE_INST_DISPLAY,
              VALS(nsmequities_orders_handle_inst_vals),
              NSMEQUITIES_ORDERS_HANDLE_INST_MASK,
              NSMEQUITIES_ORDERS_HANDLE_INST_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_inter_market_sweep_eligibility,
            { NSMEQUITIES_ORDERS_INTER_MARKET_SWEEP_ELIGIBILITY_NAME,
              NSMEQUITIES_ORDERS_INTER_MARKET_SWEEP_ELIGIBILITY_FILTER,
              NSMEQUITIES_ORDERS_INTER_MARKET_SWEEP_ELIGIBILITY_TYPE,
              NSMEQUITIES_ORDERS_INTER_MARKET_SWEEP_ELIGIBILITY_DISPLAY,
              VALS(nsmequities_orders_inter_market_sweep_eligibility_vals),
              NSMEQUITIES_ORDERS_INTER_MARKET_SWEEP_ELIGIBILITY_MASK,
              NSMEQUITIES_ORDERS_INTER_MARKET_SWEEP_ELIGIBILITY_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_intermarket_sweep_eligibility,
            { NSMEQUITIES_ORDERS_INTERMARKET_SWEEP_ELIGIBILITY_NAME,
              NSMEQUITIES_ORDERS_INTERMARKET_SWEEP_ELIGIBILITY_FILTER,
              NSMEQUITIES_ORDERS_INTERMARKET_SWEEP_ELIGIBILITY_TYPE,
              NSMEQUITIES_ORDERS_INTERMARKET_SWEEP_ELIGIBILITY_DISPLAY,
              VALS(nsmequities_orders_intermarket_sweep_eligibility_vals),
              NSMEQUITIES_ORDERS_INTERMARKET_SWEEP_ELIGIBILITY_MASK,
              NULL,
              HFILL } },
        { &hf_nsmequities_orders_liquidity_flag,
            { NSMEQUITIES_ORDERS_LIQUIDITY_FLAG_NAME,
              NSMEQUITIES_ORDERS_LIQUIDITY_FLAG_FILTER,
              NSMEQUITIES_ORDERS_LIQUIDITY_FLAG_TYPE,
              NSMEQUITIES_ORDERS_LIQUIDITY_FLAG_DISPLAY,
              VALS(nsmequities_orders_liquidity_flag_vals),
              NSMEQUITIES_ORDERS_LIQUIDITY_FLAG_MASK,
              NSMEQUITIES_ORDERS_LIQUIDITY_FLAG_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_locate_broker,
            { NSMEQUITIES_ORDERS_LOCATE_BROKER_NAME,
              NSMEQUITIES_ORDERS_LOCATE_BROKER_FILTER,
              NSMEQUITIES_ORDERS_LOCATE_BROKER_TYPE,
              NSMEQUITIES_ORDERS_LOCATE_BROKER_DISPLAY,
              NULL,
              NSMEQUITIES_ORDERS_LOCATE_BROKER_MASK,
              NSMEQUITIES_ORDERS_LOCATE_BROKER_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_mass_cancel_request_optional_field,
            { NSMEQUITIES_ORDERS_MASS_CANCEL_REQUEST_OPTIONAL_FIELD_NAME,
              NSMEQUITIES_ORDERS_MASS_CANCEL_REQUEST_OPTIONAL_FIELD_FILTER,
              NSMEQUITIES_ORDERS_MASS_CANCEL_REQUEST_OPTIONAL_FIELD_TYPE,
              NSMEQUITIES_ORDERS_MASS_CANCEL_REQUEST_OPTIONAL_FIELD_DISPLAY,
              VALS(nsmequities_orders_mass_cancel_request_optional_field_vals),
              NSMEQUITIES_ORDERS_MASS_CANCEL_REQUEST_OPTIONAL_FIELD_MASK,
              NSMEQUITIES_ORDERS_MASS_CANCEL_REQUEST_OPTIONAL_FIELD_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_mass_cancel_response_optional_field,
            { NSMEQUITIES_ORDERS_MASS_CANCEL_RESPONSE_OPTIONAL_FIELD_NAME,
              NSMEQUITIES_ORDERS_MASS_CANCEL_RESPONSE_OPTIONAL_FIELD_FILTER,
              NSMEQUITIES_ORDERS_MASS_CANCEL_RESPONSE_OPTIONAL_FIELD_TYPE,
              NSMEQUITIES_ORDERS_MASS_CANCEL_RESPONSE_OPTIONAL_FIELD_DISPLAY,
              VALS(nsmequities_orders_mass_cancel_response_optional_field_vals),
              NSMEQUITIES_ORDERS_MASS_CANCEL_RESPONSE_OPTIONAL_FIELD_MASK,
              NSMEQUITIES_ORDERS_MASS_CANCEL_RESPONSE_OPTIONAL_FIELD_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_match_number,
            { NSMEQUITIES_ORDERS_MATCH_NUMBER_NAME,
              NSMEQUITIES_ORDERS_MATCH_NUMBER_FILTER,
              NSMEQUITIES_ORDERS_MATCH_NUMBER_TYPE,
              NSMEQUITIES_ORDERS_MATCH_NUMBER_DISPLAY,
              NULL,
              NSMEQUITIES_ORDERS_MATCH_NUMBER_MASK,
              NSMEQUITIES_ORDERS_MATCH_NUMBER_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_max_floor,
            { NSMEQUITIES_ORDERS_MAX_FLOOR_NAME,
              NSMEQUITIES_ORDERS_MAX_FLOOR_FILTER,
              NSMEQUITIES_ORDERS_MAX_FLOOR_TYPE,
              NSMEQUITIES_ORDERS_MAX_FLOOR_DISPLAY,
              NULL,
              NSMEQUITIES_ORDERS_MAX_FLOOR_MASK,
              NSMEQUITIES_ORDERS_MAX_FLOOR_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_min_qty,
            { NSMEQUITIES_ORDERS_MIN_QTY_NAME,
              NSMEQUITIES_ORDERS_MIN_QTY_FILTER,
              NSMEQUITIES_ORDERS_MIN_QTY_TYPE,
              NSMEQUITIES_ORDERS_MIN_QTY_DISPLAY,
              NULL,
              NSMEQUITIES_ORDERS_MIN_QTY_MASK,
              NSMEQUITIES_ORDERS_MIN_QTY_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_minimum_quantity,
            { NSMEQUITIES_ORDERS_MINIMUM_QUANTITY_NAME,
              NSMEQUITIES_ORDERS_MINIMUM_QUANTITY_FILTER,
              NSMEQUITIES_ORDERS_MINIMUM_QUANTITY_TYPE,
              NSMEQUITIES_ORDERS_MINIMUM_QUANTITY_DISPLAY,
              NULL,
              NSMEQUITIES_ORDERS_MINIMUM_QUANTITY_MASK,
              NSMEQUITIES_ORDERS_MINIMUM_QUANTITY_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_modify_order_optional_field,
            { NSMEQUITIES_ORDERS_MODIFY_ORDER_OPTIONAL_FIELD_NAME,
              NSMEQUITIES_ORDERS_MODIFY_ORDER_OPTIONAL_FIELD_FILTER,
              NSMEQUITIES_ORDERS_MODIFY_ORDER_OPTIONAL_FIELD_TYPE,
              NSMEQUITIES_ORDERS_MODIFY_ORDER_OPTIONAL_FIELD_DISPLAY,
              VALS(nsmequities_orders_modify_order_optional_field_vals),
              NSMEQUITIES_ORDERS_MODIFY_ORDER_OPTIONAL_FIELD_MASK,
              NSMEQUITIES_ORDERS_MODIFY_ORDER_OPTIONAL_FIELD_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_next_user_ref_num,
            { NSMEQUITIES_ORDERS_NEXT_USER_REF_NUM_NAME,
              NSMEQUITIES_ORDERS_NEXT_USER_REF_NUM_FILTER,
              NSMEQUITIES_ORDERS_NEXT_USER_REF_NUM_TYPE,
              NSMEQUITIES_ORDERS_NEXT_USER_REF_NUM_DISPLAY,
              NULL,
              NSMEQUITIES_ORDERS_NEXT_USER_REF_NUM_MASK,
              NSMEQUITIES_ORDERS_NEXT_USER_REF_NUM_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_optional_field_length,
            { NSMEQUITIES_ORDERS_OPTIONAL_FIELD_LENGTH_NAME,
              NSMEQUITIES_ORDERS_OPTIONAL_FIELD_LENGTH_FILTER,
              NSMEQUITIES_ORDERS_OPTIONAL_FIELD_LENGTH_TYPE,
              NSMEQUITIES_ORDERS_OPTIONAL_FIELD_LENGTH_DISPLAY,
              NULL,
              NSMEQUITIES_ORDERS_OPTIONAL_FIELD_LENGTH_MASK,
              NSMEQUITIES_ORDERS_OPTIONAL_FIELD_LENGTH_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_order_accepted_optional_field,
            { NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_NAME,
              NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_FILTER,
              NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_TYPE,
              NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_DISPLAY,
              VALS(nsmequities_orders_order_accepted_optional_field_vals),
              NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_MASK,
              NSMEQUITIES_ORDERS_ORDER_ACCEPTED_OPTIONAL_FIELD_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_order_cancel_reason,
            { NSMEQUITIES_ORDERS_ORDER_CANCEL_REASON_NAME,
              NSMEQUITIES_ORDERS_ORDER_CANCEL_REASON_FILTER,
              NSMEQUITIES_ORDERS_ORDER_CANCEL_REASON_TYPE,
              NSMEQUITIES_ORDERS_ORDER_CANCEL_REASON_DISPLAY,
              NULL,
              NSMEQUITIES_ORDERS_ORDER_CANCEL_REASON_MASK,
              NSMEQUITIES_ORDERS_ORDER_CANCEL_REASON_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_order_executed_optional_field,
            { NSMEQUITIES_ORDERS_ORDER_EXECUTED_OPTIONAL_FIELD_NAME,
              NSMEQUITIES_ORDERS_ORDER_EXECUTED_OPTIONAL_FIELD_FILTER,
              NSMEQUITIES_ORDERS_ORDER_EXECUTED_OPTIONAL_FIELD_TYPE,
              NSMEQUITIES_ORDERS_ORDER_EXECUTED_OPTIONAL_FIELD_DISPLAY,
              VALS(nsmequities_orders_order_executed_optional_field_vals),
              NSMEQUITIES_ORDERS_ORDER_EXECUTED_OPTIONAL_FIELD_MASK,
              NSMEQUITIES_ORDERS_ORDER_EXECUTED_OPTIONAL_FIELD_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_order_modified_optional_field,
            { NSMEQUITIES_ORDERS_ORDER_MODIFIED_OPTIONAL_FIELD_NAME,
              NSMEQUITIES_ORDERS_ORDER_MODIFIED_OPTIONAL_FIELD_FILTER,
              NSMEQUITIES_ORDERS_ORDER_MODIFIED_OPTIONAL_FIELD_TYPE,
              NSMEQUITIES_ORDERS_ORDER_MODIFIED_OPTIONAL_FIELD_DISPLAY,
              VALS(nsmequities_orders_order_modified_optional_field_vals),
              NSMEQUITIES_ORDERS_ORDER_MODIFIED_OPTIONAL_FIELD_MASK,
              NSMEQUITIES_ORDERS_ORDER_MODIFIED_OPTIONAL_FIELD_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_order_priority_update_optional_field,
            { NSMEQUITIES_ORDERS_ORDER_PRIORITY_UPDATE_OPTIONAL_FIELD_NAME,
              NSMEQUITIES_ORDERS_ORDER_PRIORITY_UPDATE_OPTIONAL_FIELD_FILTER,
              NSMEQUITIES_ORDERS_ORDER_PRIORITY_UPDATE_OPTIONAL_FIELD_TYPE,
              NSMEQUITIES_ORDERS_ORDER_PRIORITY_UPDATE_OPTIONAL_FIELD_DISPLAY,
              VALS(nsmequities_orders_order_priority_update_optional_field_vals),
              NSMEQUITIES_ORDERS_ORDER_PRIORITY_UPDATE_OPTIONAL_FIELD_MASK,
              NSMEQUITIES_ORDERS_ORDER_PRIORITY_UPDATE_OPTIONAL_FIELD_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_order_reference_number,
            { NSMEQUITIES_ORDERS_ORDER_REFERENCE_NUMBER_NAME,
              NSMEQUITIES_ORDERS_ORDER_REFERENCE_NUMBER_FILTER,
              NSMEQUITIES_ORDERS_ORDER_REFERENCE_NUMBER_TYPE,
              NSMEQUITIES_ORDERS_ORDER_REFERENCE_NUMBER_DISPLAY,
              NULL,
              NSMEQUITIES_ORDERS_ORDER_REFERENCE_NUMBER_MASK,
              NSMEQUITIES_ORDERS_ORDER_REFERENCE_NUMBER_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_order_restated_optional_field,
            { NSMEQUITIES_ORDERS_ORDER_RESTATED_OPTIONAL_FIELD_NAME,
              NSMEQUITIES_ORDERS_ORDER_RESTATED_OPTIONAL_FIELD_FILTER,
              NSMEQUITIES_ORDERS_ORDER_RESTATED_OPTIONAL_FIELD_TYPE,
              NSMEQUITIES_ORDERS_ORDER_RESTATED_OPTIONAL_FIELD_DISPLAY,
              VALS(nsmequities_orders_order_restated_optional_field_vals),
              NSMEQUITIES_ORDERS_ORDER_RESTATED_OPTIONAL_FIELD_MASK,
              NSMEQUITIES_ORDERS_ORDER_RESTATED_OPTIONAL_FIELD_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_order_restated_reason,
            { NSMEQUITIES_ORDERS_ORDER_RESTATED_REASON_NAME,
              NSMEQUITIES_ORDERS_ORDER_RESTATED_REASON_FILTER,
              NSMEQUITIES_ORDERS_ORDER_RESTATED_REASON_TYPE,
              NSMEQUITIES_ORDERS_ORDER_RESTATED_REASON_DISPLAY,
              VALS(nsmequities_orders_order_restated_reason_vals),
              NSMEQUITIES_ORDERS_ORDER_RESTATED_REASON_MASK,
              NSMEQUITIES_ORDERS_ORDER_RESTATED_REASON_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_order_state,
            { NSMEQUITIES_ORDERS_ORDER_STATE_NAME,
              NSMEQUITIES_ORDERS_ORDER_STATE_FILTER,
              NSMEQUITIES_ORDERS_ORDER_STATE_TYPE,
              NSMEQUITIES_ORDERS_ORDER_STATE_DISPLAY,
              VALS(nsmequities_orders_order_state_vals),
              NSMEQUITIES_ORDERS_ORDER_STATE_MASK,
              NULL,
              HFILL } },
        { &hf_nsmequities_orders_order_token,
            { NSMEQUITIES_ORDERS_ORDER_TOKEN_NAME,
              NSMEQUITIES_ORDERS_ORDER_TOKEN_FILTER,
              NSMEQUITIES_ORDERS_ORDER_TOKEN_TYPE,
              NSMEQUITIES_ORDERS_ORDER_TOKEN_DISPLAY,
              NULL,
              NSMEQUITIES_ORDERS_ORDER_TOKEN_MASK,
              NSMEQUITIES_ORDERS_ORDER_TOKEN_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_orig_user_ref_num,
            { NSMEQUITIES_ORDERS_ORIG_USER_REF_NUM_NAME,
              NSMEQUITIES_ORDERS_ORIG_USER_REF_NUM_FILTER,
              NSMEQUITIES_ORDERS_ORIG_USER_REF_NUM_TYPE,
              NSMEQUITIES_ORDERS_ORIG_USER_REF_NUM_DISPLAY,
              NULL,
              NSMEQUITIES_ORDERS_ORIG_USER_REF_NUM_MASK,
              NSMEQUITIES_ORDERS_ORIG_USER_REF_NUM_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_packet_length,
            { NSMEQUITIES_ORDERS_PACKET_LENGTH_NAME,
              NSMEQUITIES_ORDERS_PACKET_LENGTH_FILTER,
              NSMEQUITIES_ORDERS_PACKET_LENGTH_TYPE,
              NSMEQUITIES_ORDERS_PACKET_LENGTH_DISPLAY,
              NULL,
              NSMEQUITIES_ORDERS_PACKET_LENGTH_MASK,
              NSMEQUITIES_ORDERS_PACKET_LENGTH_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_password,
            { NSMEQUITIES_ORDERS_PASSWORD_NAME,
              NSMEQUITIES_ORDERS_PASSWORD_FILTER,
              NSMEQUITIES_ORDERS_PASSWORD_TYPE,
              NSMEQUITIES_ORDERS_PASSWORD_DISPLAY,
              NULL,
              NSMEQUITIES_ORDERS_PASSWORD_MASK,
              NSMEQUITIES_ORDERS_PASSWORD_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_peg_offset,
            { NSMEQUITIES_ORDERS_PEG_OFFSET_NAME,
              NSMEQUITIES_ORDERS_PEG_OFFSET_FILTER,
              NSMEQUITIES_ORDERS_PEG_OFFSET_TYPE,
              NSMEQUITIES_ORDERS_PEG_OFFSET_DISPLAY,
              CF_FUNC(nsmequities_orders_format_decimal_4_32),
              NSMEQUITIES_ORDERS_PEG_OFFSET_MASK,
              NSMEQUITIES_ORDERS_PEG_OFFSET_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_post_only,
            { NSMEQUITIES_ORDERS_POST_ONLY_NAME,
              NSMEQUITIES_ORDERS_POST_ONLY_FILTER,
              NSMEQUITIES_ORDERS_POST_ONLY_TYPE,
              NSMEQUITIES_ORDERS_POST_ONLY_DISPLAY,
              VALS(nsmequities_orders_post_only_vals),
              NSMEQUITIES_ORDERS_POST_ONLY_MASK,
              NSMEQUITIES_ORDERS_POST_ONLY_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_previous_order_token,
            { NSMEQUITIES_ORDERS_PREVIOUS_ORDER_TOKEN_NAME,
              NSMEQUITIES_ORDERS_PREVIOUS_ORDER_TOKEN_FILTER,
              NSMEQUITIES_ORDERS_PREVIOUS_ORDER_TOKEN_TYPE,
              NSMEQUITIES_ORDERS_PREVIOUS_ORDER_TOKEN_DISPLAY,
              NULL,
              NSMEQUITIES_ORDERS_PREVIOUS_ORDER_TOKEN_MASK,
              NSMEQUITIES_ORDERS_PREVIOUS_ORDER_TOKEN_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_price,
            { NSMEQUITIES_ORDERS_PRICE_NAME,
              NSMEQUITIES_ORDERS_PRICE_FILTER,
              NSMEQUITIES_ORDERS_PRICE_TYPE,
              NSMEQUITIES_ORDERS_PRICE_DISPLAY,
              CF_FUNC(nsmequities_orders_format_decimal_4_64_unsigned),
              NSMEQUITIES_ORDERS_PRICE_MASK,
              NSMEQUITIES_ORDERS_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_price_v422018,
            { NSMEQUITIES_ORDERS_PRICE_V422018_NAME,
              NSMEQUITIES_ORDERS_PRICE_V422018_FILTER,
              NSMEQUITIES_ORDERS_PRICE_V422018_TYPE,
              NSMEQUITIES_ORDERS_PRICE_V422018_DISPLAY,
              CF_FUNC(nsmequities_orders_format_decimal_4_32_unsigned),
              NSMEQUITIES_ORDERS_PRICE_V422018_MASK,
              NSMEQUITIES_ORDERS_PRICE_V422018_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_price_type,
            { NSMEQUITIES_ORDERS_PRICE_TYPE_NAME,
              NSMEQUITIES_ORDERS_PRICE_TYPE_FILTER,
              NSMEQUITIES_ORDERS_PRICE_TYPE_TYPE,
              NSMEQUITIES_ORDERS_PRICE_TYPE_DISPLAY,
              VALS(nsmequities_orders_price_type_vals),
              NSMEQUITIES_ORDERS_PRICE_TYPE_MASK,
              NSMEQUITIES_ORDERS_PRICE_TYPE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_quantity,
            { NSMEQUITIES_ORDERS_QUANTITY_NAME,
              NSMEQUITIES_ORDERS_QUANTITY_FILTER,
              NSMEQUITIES_ORDERS_QUANTITY_TYPE,
              NSMEQUITIES_ORDERS_QUANTITY_DISPLAY,
              NULL,
              NSMEQUITIES_ORDERS_QUANTITY_MASK,
              NSMEQUITIES_ORDERS_QUANTITY_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_quantity_prevented_from_trading,
            { NSMEQUITIES_ORDERS_QUANTITY_PREVENTED_FROM_TRADING_NAME,
              NSMEQUITIES_ORDERS_QUANTITY_PREVENTED_FROM_TRADING_FILTER,
              NSMEQUITIES_ORDERS_QUANTITY_PREVENTED_FROM_TRADING_TYPE,
              NSMEQUITIES_ORDERS_QUANTITY_PREVENTED_FROM_TRADING_DISPLAY,
              NULL,
              NSMEQUITIES_ORDERS_QUANTITY_PREVENTED_FROM_TRADING_MASK,
              NSMEQUITIES_ORDERS_QUANTITY_PREVENTED_FROM_TRADING_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_random_reserves,
            { NSMEQUITIES_ORDERS_RANDOM_RESERVES_NAME,
              NSMEQUITIES_ORDERS_RANDOM_RESERVES_FILTER,
              NSMEQUITIES_ORDERS_RANDOM_RESERVES_TYPE,
              NSMEQUITIES_ORDERS_RANDOM_RESERVES_DISPLAY,
              NULL,
              NSMEQUITIES_ORDERS_RANDOM_RESERVES_MASK,
              NSMEQUITIES_ORDERS_RANDOM_RESERVES_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_reason,
            { NSMEQUITIES_ORDERS_REASON_NAME,
              NSMEQUITIES_ORDERS_REASON_FILTER,
              NSMEQUITIES_ORDERS_REASON_TYPE,
              NSMEQUITIES_ORDERS_REASON_DISPLAY,
              VALS(nsmequities_orders_reason_vals),
              NSMEQUITIES_ORDERS_REASON_MASK,
              NSMEQUITIES_ORDERS_REASON_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_reference_price,
            { NSMEQUITIES_ORDERS_REFERENCE_PRICE_NAME,
              NSMEQUITIES_ORDERS_REFERENCE_PRICE_FILTER,
              NSMEQUITIES_ORDERS_REFERENCE_PRICE_TYPE,
              NSMEQUITIES_ORDERS_REFERENCE_PRICE_DISPLAY,
              CF_FUNC(nsmequities_orders_format_decimal_4_32_unsigned),
              NSMEQUITIES_ORDERS_REFERENCE_PRICE_MASK,
              NSMEQUITIES_ORDERS_REFERENCE_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_reference_price_type,
            { NSMEQUITIES_ORDERS_REFERENCE_PRICE_TYPE_NAME,
              NSMEQUITIES_ORDERS_REFERENCE_PRICE_TYPE_FILTER,
              NSMEQUITIES_ORDERS_REFERENCE_PRICE_TYPE_TYPE,
              NSMEQUITIES_ORDERS_REFERENCE_PRICE_TYPE_DISPLAY,
              VALS(nsmequities_orders_reference_price_type_vals),
              NSMEQUITIES_ORDERS_REFERENCE_PRICE_TYPE_MASK,
              NSMEQUITIES_ORDERS_REFERENCE_PRICE_TYPE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_reject_reason_code,
            { NSMEQUITIES_ORDERS_REJECT_REASON_CODE_NAME,
              NSMEQUITIES_ORDERS_REJECT_REASON_CODE_FILTER,
              NSMEQUITIES_ORDERS_REJECT_REASON_CODE_TYPE,
              NSMEQUITIES_ORDERS_REJECT_REASON_CODE_DISPLAY,
              VALS(nsmequities_orders_reject_reason_code_vals),
              NSMEQUITIES_ORDERS_REJECT_REASON_CODE_MASK,
              NSMEQUITIES_ORDERS_REJECT_REASON_CODE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_rejected_order_optional_field,
            { NSMEQUITIES_ORDERS_REJECTED_ORDER_OPTIONAL_FIELD_NAME,
              NSMEQUITIES_ORDERS_REJECTED_ORDER_OPTIONAL_FIELD_FILTER,
              NSMEQUITIES_ORDERS_REJECTED_ORDER_OPTIONAL_FIELD_TYPE,
              NSMEQUITIES_ORDERS_REJECTED_ORDER_OPTIONAL_FIELD_DISPLAY,
              VALS(nsmequities_orders_rejected_order_optional_field_vals),
              NSMEQUITIES_ORDERS_REJECTED_ORDER_OPTIONAL_FIELD_MASK,
              NSMEQUITIES_ORDERS_REJECTED_ORDER_OPTIONAL_FIELD_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_rejected_order_reason,
            { NSMEQUITIES_ORDERS_REJECTED_ORDER_REASON_NAME,
              NSMEQUITIES_ORDERS_REJECTED_ORDER_REASON_FILTER,
              NSMEQUITIES_ORDERS_REJECTED_ORDER_REASON_TYPE,
              NSMEQUITIES_ORDERS_REJECTED_ORDER_REASON_DISPLAY,
              VALS(nsmequities_orders_rejected_order_reason_vals),
              NSMEQUITIES_ORDERS_REJECTED_ORDER_REASON_MASK,
              NSMEQUITIES_ORDERS_REJECTED_ORDER_REASON_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_rejected_order_reason_v422018,
            { NSMEQUITIES_ORDERS_REJECTED_ORDER_REASON_V422018_NAME,
              NSMEQUITIES_ORDERS_REJECTED_ORDER_REASON_V422018_FILTER,
              NSMEQUITIES_ORDERS_REJECTED_ORDER_REASON_V422018_TYPE,
              NSMEQUITIES_ORDERS_REJECTED_ORDER_REASON_V422018_DISPLAY,
              VALS(nsmequities_orders_rejected_order_reason_v422018_vals),
              NSMEQUITIES_ORDERS_REJECTED_ORDER_REASON_V422018_MASK,
              NSMEQUITIES_ORDERS_REJECTED_ORDER_REASON_V422018_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_replace_order_optional_field,
            { NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_NAME,
              NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_FILTER,
              NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_TYPE,
              NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_DISPLAY,
              VALS(nsmequities_orders_replace_order_optional_field_vals),
              NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_MASK,
              NSMEQUITIES_ORDERS_REPLACE_ORDER_OPTIONAL_FIELD_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_replaced_message_optional_field,
            { NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_NAME,
              NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_FILTER,
              NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_TYPE,
              NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_DISPLAY,
              VALS(nsmequities_orders_replaced_message_optional_field_vals),
              NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_MASK,
              NSMEQUITIES_ORDERS_REPLACED_MESSAGE_OPTIONAL_FIELD_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_replacement_order_token,
            { NSMEQUITIES_ORDERS_REPLACEMENT_ORDER_TOKEN_NAME,
              NSMEQUITIES_ORDERS_REPLACEMENT_ORDER_TOKEN_FILTER,
              NSMEQUITIES_ORDERS_REPLACEMENT_ORDER_TOKEN_TYPE,
              NSMEQUITIES_ORDERS_REPLACEMENT_ORDER_TOKEN_DISPLAY,
              NULL,
              NSMEQUITIES_ORDERS_REPLACEMENT_ORDER_TOKEN_MASK,
              NSMEQUITIES_ORDERS_REPLACEMENT_ORDER_TOKEN_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_requested_sequence_number,
            { NSMEQUITIES_ORDERS_REQUESTED_SEQUENCE_NUMBER_NAME,
              NSMEQUITIES_ORDERS_REQUESTED_SEQUENCE_NUMBER_FILTER,
              NSMEQUITIES_ORDERS_REQUESTED_SEQUENCE_NUMBER_TYPE,
              NSMEQUITIES_ORDERS_REQUESTED_SEQUENCE_NUMBER_DISPLAY,
              NULL,
              NSMEQUITIES_ORDERS_REQUESTED_SEQUENCE_NUMBER_MASK,
              NSMEQUITIES_ORDERS_REQUESTED_SEQUENCE_NUMBER_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_requested_session,
            { NSMEQUITIES_ORDERS_REQUESTED_SESSION_NAME,
              NSMEQUITIES_ORDERS_REQUESTED_SESSION_FILTER,
              NSMEQUITIES_ORDERS_REQUESTED_SESSION_TYPE,
              NSMEQUITIES_ORDERS_REQUESTED_SESSION_DISPLAY,
              NULL,
              NSMEQUITIES_ORDERS_REQUESTED_SESSION_MASK,
              NSMEQUITIES_ORDERS_REQUESTED_SESSION_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_route,
            { NSMEQUITIES_ORDERS_ROUTE_NAME,
              NSMEQUITIES_ORDERS_ROUTE_FILTER,
              NSMEQUITIES_ORDERS_ROUTE_TYPE,
              NSMEQUITIES_ORDERS_ROUTE_DISPLAY,
              NULL,
              NSMEQUITIES_ORDERS_ROUTE_MASK,
              NULL,
              HFILL } },
        { &hf_nsmequities_orders_secondary_ord_ref_num,
            { NSMEQUITIES_ORDERS_SECONDARY_ORD_REF_NUM_NAME,
              NSMEQUITIES_ORDERS_SECONDARY_ORD_REF_NUM_FILTER,
              NSMEQUITIES_ORDERS_SECONDARY_ORD_REF_NUM_TYPE,
              NSMEQUITIES_ORDERS_SECONDARY_ORD_REF_NUM_DISPLAY,
              NULL,
              NSMEQUITIES_ORDERS_SECONDARY_ORD_REF_NUM_MASK,
              NSMEQUITIES_ORDERS_SECONDARY_ORD_REF_NUM_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_sequenced_message_type,
            { NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_NAME,
              NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_FILTER,
              NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_TYPE,
              NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_DISPLAY,
              VALS(nsmequities_orders_sequenced_message_type_vals),
              NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_MASK,
              NSMEQUITIES_ORDERS_SEQUENCED_MESSAGE_TYPE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_server_packet_type,
            { NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_NAME,
              NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_FILTER,
              NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_TYPE,
              NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_DISPLAY,
              VALS(nsmequities_orders_server_packet_type_vals),
              NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_MASK,
              NSMEQUITIES_ORDERS_SERVER_PACKET_TYPE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_shares,
            { NSMEQUITIES_ORDERS_SHARES_NAME,
              NSMEQUITIES_ORDERS_SHARES_FILTER,
              NSMEQUITIES_ORDERS_SHARES_TYPE,
              NSMEQUITIES_ORDERS_SHARES_DISPLAY,
              NULL,
              NSMEQUITIES_ORDERS_SHARES_MASK,
              NSMEQUITIES_ORDERS_SHARES_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_shares_located,
            { NSMEQUITIES_ORDERS_SHARES_LOCATED_NAME,
              NSMEQUITIES_ORDERS_SHARES_LOCATED_FILTER,
              NSMEQUITIES_ORDERS_SHARES_LOCATED_TYPE,
              NSMEQUITIES_ORDERS_SHARES_LOCATED_DISPLAY,
              VALS(nsmequities_orders_shares_located_vals),
              NSMEQUITIES_ORDERS_SHARES_LOCATED_MASK,
              NSMEQUITIES_ORDERS_SHARES_LOCATED_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_side,
            { NSMEQUITIES_ORDERS_SIDE_NAME,
              NSMEQUITIES_ORDERS_SIDE_FILTER,
              NSMEQUITIES_ORDERS_SIDE_TYPE,
              NSMEQUITIES_ORDERS_SIDE_DISPLAY,
              VALS(nsmequities_orders_side_vals),
              NSMEQUITIES_ORDERS_SIDE_MASK,
              NULL,
              HFILL } },
        { &hf_nsmequities_orders_stock,
            { NSMEQUITIES_ORDERS_STOCK_NAME,
              NSMEQUITIES_ORDERS_STOCK_FILTER,
              NSMEQUITIES_ORDERS_STOCK_TYPE,
              NSMEQUITIES_ORDERS_STOCK_DISPLAY,
              NULL,
              NSMEQUITIES_ORDERS_STOCK_MASK,
              NSMEQUITIES_ORDERS_STOCK_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_symbol,
            { NSMEQUITIES_ORDERS_SYMBOL_NAME,
              NSMEQUITIES_ORDERS_SYMBOL_FILTER,
              NSMEQUITIES_ORDERS_SYMBOL_TYPE,
              NSMEQUITIES_ORDERS_SYMBOL_DISPLAY,
              NULL,
              NSMEQUITIES_ORDERS_SYMBOL_MASK,
              NSMEQUITIES_ORDERS_SYMBOL_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_time_in_force,
            { NSMEQUITIES_ORDERS_TIME_IN_FORCE_NAME,
              NSMEQUITIES_ORDERS_TIME_IN_FORCE_FILTER,
              NSMEQUITIES_ORDERS_TIME_IN_FORCE_TYPE,
              NSMEQUITIES_ORDERS_TIME_IN_FORCE_DISPLAY,
              VALS(nsmequities_orders_time_in_force_vals),
              NSMEQUITIES_ORDERS_TIME_IN_FORCE_MASK,
              NSMEQUITIES_ORDERS_TIME_IN_FORCE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_time_in_force_v422018,
            { NSMEQUITIES_ORDERS_TIME_IN_FORCE_V422018_NAME,
              NSMEQUITIES_ORDERS_TIME_IN_FORCE_V422018_FILTER,
              NSMEQUITIES_ORDERS_TIME_IN_FORCE_V422018_TYPE,
              NSMEQUITIES_ORDERS_TIME_IN_FORCE_V422018_DISPLAY,
              VALS(nsmequities_orders_time_in_force_v422018_vals),
              NSMEQUITIES_ORDERS_TIME_IN_FORCE_V422018_MASK,
              NSMEQUITIES_ORDERS_TIME_IN_FORCE_V422018_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_timestamp,
            { NSMEQUITIES_ORDERS_TIMESTAMP_NAME,
              NSMEQUITIES_ORDERS_TIMESTAMP_FILTER,
              NSMEQUITIES_ORDERS_TIMESTAMP_TYPE,
              NSMEQUITIES_ORDERS_TIMESTAMP_DISPLAY,
              NULL,
              NSMEQUITIES_ORDERS_TIMESTAMP_MASK,
              NSMEQUITIES_ORDERS_TIMESTAMP_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_timestamp_v422018,
            { NSMEQUITIES_ORDERS_TIMESTAMP_V422018_NAME,
              NSMEQUITIES_ORDERS_TIMESTAMP_V422018_FILTER,
              NSMEQUITIES_ORDERS_TIMESTAMP_V422018_TYPE,
              NSMEQUITIES_ORDERS_TIMESTAMP_V422018_DISPLAY,
              NULL,
              NSMEQUITIES_ORDERS_TIMESTAMP_V422018_MASK,
              NSMEQUITIES_ORDERS_TIMESTAMP_V422018_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_trade_now,
            { NSMEQUITIES_ORDERS_TRADE_NOW_NAME,
              NSMEQUITIES_ORDERS_TRADE_NOW_FILTER,
              NSMEQUITIES_ORDERS_TRADE_NOW_TYPE,
              NSMEQUITIES_ORDERS_TRADE_NOW_DISPLAY,
              VALS(nsmequities_orders_trade_now_vals),
              NSMEQUITIES_ORDERS_TRADE_NOW_MASK,
              NSMEQUITIES_ORDERS_TRADE_NOW_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_unsequenced_message_type,
            { NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_NAME,
              NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_FILTER,
              NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_TYPE,
              NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_DISPLAY,
              VALS(nsmequities_orders_unsequenced_message_type_vals),
              NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_MASK,
              NSMEQUITIES_ORDERS_UNSEQUENCED_MESSAGE_TYPE_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_user_ref_idx,
            { NSMEQUITIES_ORDERS_USER_REF_IDX_NAME,
              NSMEQUITIES_ORDERS_USER_REF_IDX_FILTER,
              NSMEQUITIES_ORDERS_USER_REF_IDX_TYPE,
              NSMEQUITIES_ORDERS_USER_REF_IDX_DISPLAY,
              NULL,
              NSMEQUITIES_ORDERS_USER_REF_IDX_MASK,
              NSMEQUITIES_ORDERS_USER_REF_IDX_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_user_ref_num,
            { NSMEQUITIES_ORDERS_USER_REF_NUM_NAME,
              NSMEQUITIES_ORDERS_USER_REF_NUM_FILTER,
              NSMEQUITIES_ORDERS_USER_REF_NUM_TYPE,
              NSMEQUITIES_ORDERS_USER_REF_NUM_DISPLAY,
              NULL,
              NSMEQUITIES_ORDERS_USER_REF_NUM_MASK,
              NSMEQUITIES_ORDERS_USER_REF_NUM_DESCRIPTION,
              HFILL } },
        { &hf_nsmequities_orders_username,
            { NSMEQUITIES_ORDERS_USERNAME_NAME,
              NSMEQUITIES_ORDERS_USERNAME_FILTER,
              NSMEQUITIES_ORDERS_USERNAME_TYPE,
              NSMEQUITIES_ORDERS_USERNAME_DISPLAY,
              NULL,
              NSMEQUITIES_ORDERS_USERNAME_MASK,
              NSMEQUITIES_ORDERS_USERNAME_DESCRIPTION,
              HFILL } },

        /* Generated */
        { &hf_nsmequities_orders_time_of_day,
            { NSMEQUITIES_ORDERS_TIME_OF_DAY_NAME,
              NSMEQUITIES_ORDERS_TIME_OF_DAY_FILTER,
              FT_RELATIVE_TIME,
              BASE_NONE,
              NULL,
              0x0,
              NSMEQUITIES_ORDERS_TIME_OF_DAY_DESCRIPTION,
              HFILL } },

        { &hf_nsmequities_orders_utc,
            { NSMEQUITIES_ORDERS_UTC_NAME,
              NSMEQUITIES_ORDERS_UTC_FILTER,
              FT_ABSOLUTE_TIME,
              ABSOLUTE_TIME_UTC,
              NULL,
              0x0,
              NSMEQUITIES_ORDERS_UTC_DESCRIPTION,
              HFILL } },

        { &hf_nsmequities_orders_local,
            { NSMEQUITIES_ORDERS_LOCAL_NAME,
              NSMEQUITIES_ORDERS_LOCAL_FILTER,
              FT_ABSOLUTE_TIME,
              ABSOLUTE_TIME_LOCAL,
              NULL,
              0x0,
              NSMEQUITIES_ORDERS_LOCAL_DESCRIPTION,
              HFILL } },

        { &hf_nsmequities_orders_elapsed_nanoseconds,
            { NSMEQUITIES_ORDERS_ELAPSED_NANOSECONDS_NAME,
              NSMEQUITIES_ORDERS_ELAPSED_NANOSECONDS_FILTER,
              FT_UINT64,
              BASE_DEC,
              NULL,
              0x0,
              NSMEQUITIES_ORDERS_ELAPSED_NANOSECONDS_DESCRIPTION,
              HFILL } },
    };

    static int *ett[] = {
        &ett_nsmequities_orders,
        &ett_nsmequities_orders_header,
        &ett_nsmequities_orders_message,
        &ett_nsmequities_orders_timestamp,
        &ett_nsmequities_orders_client_packet_header,
        &ett_nsmequities_orders_enter_order_appendage,
        &ett_nsmequities_orders_replace_order_appendage,
        &ett_nsmequities_orders_cancel_order_appendage,
        &ett_nsmequities_orders_modify_order_appendage,
        &ett_nsmequities_orders_account_query_appendage,
        &ett_nsmequities_orders_mass_cancel_request_appendage,
        &ett_nsmequities_orders_disable_order_entry_request_appendage,
        &ett_nsmequities_orders_enable_order_entry_request_appendage,
        &ett_nsmequities_orders_server_packet_header,
        &ett_nsmequities_orders_order_accepted_appendage,
        &ett_nsmequities_orders_replaced_message_appendage,
        &ett_nsmequities_orders_canceled_message_appendage,
        &ett_nsmequities_orders_aiq_canceled_appendage,
        &ett_nsmequities_orders_order_executed_appendage,
        &ett_nsmequities_orders_broken_trade_appendage,
        &ett_nsmequities_orders_rejected_order_appendage,
        &ett_nsmequities_orders_cancel_pending_appendage,
        &ett_nsmequities_orders_cancel_reject_appendage,
        &ett_nsmequities_orders_order_priority_update_appendage,
        &ett_nsmequities_orders_order_modified_appendage,
        &ett_nsmequities_orders_order_restated_appendage,
        &ett_nsmequities_orders_account_query_response_appendage,
        &ett_nsmequities_orders_mass_cancel_response_appendage,
        &ett_nsmequities_orders_disable_order_entry_response_appendage,
        &ett_nsmequities_orders_enable_order_entry_response_appendage,
    };

    static ei_register_info ei[] = {
        { &ei_nsmequities_orders_length,
            { NSMEQUITIES_ORDERS_LENGTH_EXPERT_FILTER,
              NSMEQUITIES_ORDERS_LENGTH_EXPERT_GROUP,
              NSMEQUITIES_ORDERS_LENGTH_EXPERT_SEVERITY,
              NSMEQUITIES_ORDERS_LENGTH_EXPERT_SUMMARY,
              EXPFILL } },
    };

    proto_nsmequities_orders = proto_register_protocol(NSMEQUITIES_ORDERS_PROTOCOL_NAME, NSMEQUITIES_ORDERS_PROTOCOL_SHORT, NSMEQUITIES_ORDERS_PROTOCOL_FILTER);

    proto_register_field_array(proto_nsmequities_orders, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_module_t *expert_nsmequities_orders = expert_register_protocol(proto_nsmequities_orders);
    expert_register_field_array(expert_nsmequities_orders, ei, array_length(ei));

    module_t *preferences = prefs_register_protocol(proto_nsmequities_orders, NULL);

    prefs_register_enum_preference(
        preferences,
        NSMEQUITIES_ORDERS_VERSION_PREFERENCE_NAME,
        NSMEQUITIES_ORDERS_VERSION_PREFERENCE_TITLE,
        NSMEQUITIES_ORDERS_VERSION_PREFERENCE_DESCRIPTION,
        &nsmequities_orders_pref_version,
        nsmequities_orders_version_vals,
        false);

    prefs_register_bool_preference(
        preferences,
        NSMEQUITIES_ORDERS_SHOW_HEADERS_PREFERENCE_NAME,
        NSMEQUITIES_ORDERS_SHOW_HEADERS_PREFERENCE_TITLE,
        NSMEQUITIES_ORDERS_SHOW_HEADERS_PREFERENCE_DESCRIPTION,
        &nsmequities_orders_show_headers);

    prefs_register_bool_preference(
        preferences,
        NSMEQUITIES_ORDERS_SHOW_SESSION_MESSAGES_PREFERENCE_NAME,
        NSMEQUITIES_ORDERS_SHOW_SESSION_MESSAGES_PREFERENCE_TITLE,
        NSMEQUITIES_ORDERS_SHOW_SESSION_MESSAGES_PREFERENCE_DESCRIPTION,
        &nsmequities_orders_show_session_messages);

    prefs_register_bool_preference(
        preferences,
        NSMEQUITIES_ORDERS_SHOW_APPLICATION_MESSAGES_PREFERENCE_NAME,
        NSMEQUITIES_ORDERS_SHOW_APPLICATION_MESSAGES_PREFERENCE_TITLE,
        NSMEQUITIES_ORDERS_SHOW_APPLICATION_MESSAGES_PREFERENCE_DESCRIPTION,
        &nsmequities_orders_show_application_messages);

    prefs_register_bool_preference(
        preferences,
        NSMEQUITIES_ORDERS_SHOW_STRUCTS_PREFERENCE_NAME,
        NSMEQUITIES_ORDERS_SHOW_STRUCTS_PREFERENCE_TITLE,
        NSMEQUITIES_ORDERS_SHOW_STRUCTS_PREFERENCE_DESCRIPTION,
        &nsmequities_orders_show_structs);

    prefs_register_uint_preference(
        preferences,
        NSMEQUITIES_ORDERS_DECIMAL_PREFERENCE_NAME,
        NSMEQUITIES_ORDERS_DECIMAL_PREFERENCE_TITLE,
        NSMEQUITIES_ORDERS_DECIMAL_PREFERENCE_DESCRIPTION,
        10,
        &nsmequities_orders_pref_decimal_places);

    prefs_register_bool_preference(
        preferences,
        NSMEQUITIES_ORDERS_READ_TIMESTAMP_PREFERENCE_NAME,
        NSMEQUITIES_ORDERS_READ_TIMESTAMP_PREFERENCE_TITLE,
        NSMEQUITIES_ORDERS_READ_TIMESTAMP_PREFERENCE_DESCRIPTION,
        &nsmequities_orders_pref_read_timestamp);

    prefs_register_enum_preference(
        preferences,
        NSMEQUITIES_ORDERS_ASSUME_ROLE_PREFERENCE_NAME,
        NSMEQUITIES_ORDERS_ASSUME_ROLE_PREFERENCE_TITLE,
        NSMEQUITIES_ORDERS_ASSUME_ROLE_PREFERENCE_DESCRIPTION,
        &nsmequities_orders_pref_assume_role,
        nsmequities_orders_assume_role_vals,
        false);

    prefs_register_uint_preference(
        preferences,
        NSMEQUITIES_ORDERS_ACCEPTOR_PORT_PREFERENCE_NAME,
        NSMEQUITIES_ORDERS_ACCEPTOR_PORT_PREFERENCE_TITLE,
        NSMEQUITIES_ORDERS_ACCEPTOR_PORT_PREFERENCE_DESCRIPTION,
        10,
        &nsmequities_orders_pref_acceptor_port);

    prefs_register_bool_preference(
        preferences,
        NSMEQUITIES_ORDERS_SWAP_SIDES_PREFERENCE_NAME,
        NSMEQUITIES_ORDERS_SWAP_SIDES_PREFERENCE_TITLE,
        NSMEQUITIES_ORDERS_SWAP_SIDES_PREFERENCE_DESCRIPTION,
        &nsmequities_orders_pref_swap_sides);

    range_convert_str(
        wmem_epan_scope(),
        &nsmequities_orders_pref_ports,
        NSMEQUITIES_ORDERS_PORTS_PREFERENCE_DEFAULT,
        NSMEQUITIES_ORDERS_PORTS_PREFERENCE_MAXIMUM);
    prefs_register_range_preference(
        preferences,
        NSMEQUITIES_ORDERS_PORTS_PREFERENCE_NAME,
        NSMEQUITIES_ORDERS_PORTS_PREFERENCE_TITLE,
        NSMEQUITIES_ORDERS_PORTS_PREFERENCE_DESCRIPTION,
        &nsmequities_orders_pref_ports,
        NSMEQUITIES_ORDERS_PORTS_PREFERENCE_MAXIMUM);

    nsmequities_orders_handle = register_dissector(NSMEQUITIES_ORDERS_PROTOCOL_FILTER, dissect_nsmequities_orders, proto_nsmequities_orders);
}

void
proto_reg_handoff_nsmequities_orders(void)
{
    heur_dissector_add("tcp", dissect_nsmequities_orders_heur, "Nasdaq Ouch Orders over TCP",
        "nsmequities_orders_tcp", proto_nsmequities_orders, HEURISTIC_ENABLE);

    dissector_add_for_decode_as("tcp.port", nsmequities_orders_handle);
}
