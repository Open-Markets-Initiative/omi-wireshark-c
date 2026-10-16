/* packet-deribit-ordersapi.c
 * Routines for Deribit OrdersApi dissection
 *
 * Aggregated protocol versions: 1.5, 1.4, 1.3, 1.0, 0.1
 * Version selection: automatic by send time, or forced by preference
 *
 * Generated from the Omi binary model library
 *
 * Models:
 *   Coinbase.Deribit.OrdersApi.Sbe.v1.5
 *   Coinbase.Deribit.OrdersApi.Sbe.v1.4
 *   Coinbase.Deribit.OrdersApi.Sbe.v1.3
 *   Coinbase.Deribit.OrdersApi.Sbe.v1.0
 *   Coinbase.Deribit.OrdersApi.Sbe.v0.1
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
#include <wsutil/array.h>

void proto_register_deribit_ordersapi(void);
void proto_reg_handoff_deribit_ordersapi(void);

static dissector_handle_t deribit_ordersapi_handle;

static int proto_deribit_ordersapi;

/*
 * Deribit OrdersApi Protocol
 */

#define DERIBIT_ORDERSAPI_PROTOCOL_NAME "Deribit OrdersApi"
#define DERIBIT_ORDERSAPI_PROTOCOL_SHORT "DERIBIT.ORDERSAPI"
#define DERIBIT_ORDERSAPI_PROTOCOL_FILTER "deribit.ordersapi"

/*
 * Deribit OrdersApi Header
 */

#define DERIBIT_ORDERSAPI_HEADER_SIZE 32 /* Sbe Message */

/*
 * Deribit OrdersApi Field Handles
 */

static int hf_deribit_ordersapi_ask_flags;
static int hf_deribit_ordersapi_ask_flags_v10;
static int hf_deribit_ordersapi_ask_order_id;
static int hf_deribit_ordersapi_ask_price;
static int hf_deribit_ordersapi_ask_price_optional;
static int hf_deribit_ordersapi_ask_reject_reason;
static int hf_deribit_ordersapi_ask_status;
static int hf_deribit_ordersapi_bid_flags;
static int hf_deribit_ordersapi_bid_flags_v10;
static int hf_deribit_ordersapi_bid_order_id;
static int hf_deribit_ordersapi_bid_price;
static int hf_deribit_ordersapi_bid_price_optional;
static int hf_deribit_ordersapi_bid_reject_reason;
static int hf_deribit_ordersapi_bid_status;
static int hf_deribit_ordersapi_block_length;
static int hf_deribit_ordersapi_cancel_on_disconnect;
static int hf_deribit_ordersapi_cancel_reason;
static int hf_deribit_ordersapi_client_id;
static int hf_deribit_ordersapi_client_order_id;
static int hf_deribit_ordersapi_correlation_id;
static int hf_deribit_ordersapi_correlation_id_optional;
static int hf_deribit_ordersapi_currency_pair_id;
static int hf_deribit_ordersapi_delta_level;
static int hf_deribit_ordersapi_details_data;
static int hf_deribit_ordersapi_details_length;
static int hf_deribit_ordersapi_exec_id;
static int hf_deribit_ordersapi_exponent;
static int hf_deribit_ordersapi_fill_id;
static int hf_deribit_ordersapi_fill_price;
static int hf_deribit_ordersapi_flags_cancel_flags;
static int hf_deribit_ordersapi_flags_fill_flags;
static int hf_deribit_ordersapi_flags_mass_quote_flags;
static int hf_deribit_ordersapi_flags_multi_part_event_flags;
static int hf_deribit_ordersapi_flags_order_flags;
static int hf_deribit_ordersapi_flags_order_flags_v10;
static int hf_deribit_ordersapi_flags_replace_order_flags;
static int hf_deribit_ordersapi_from_sequence_number;
static int hf_deribit_ordersapi_frozen_until;
static int hf_deribit_ordersapi_frozen_until_time;
static int hf_deribit_ordersapi_heartbeat_interval_seconds;
static int hf_deribit_ordersapi_instrument_id;
static int hf_deribit_ordersapi_instrument_id_optional;
static int hf_deribit_ordersapi_is_fully_filled;
static int hf_deribit_ordersapi_is_last_message;
static int hf_deribit_ordersapi_is_quote;
static int hf_deribit_ordersapi_is_resend;
static int hf_deribit_ordersapi_last_processed_seq_no;
static int hf_deribit_ordersapi_leg_side;
static int hf_deribit_ordersapi_mantissa;
static int hf_deribit_ordersapi_market_limit;
static int hf_deribit_ordersapi_match_id;
static int hf_deribit_ordersapi_message_length;
static int hf_deribit_ordersapi_mmp;
static int hf_deribit_ordersapi_mmp_group_id;
static int hf_deribit_ordersapi_new_sequence_number;
static int hf_deribit_ordersapi_num_in_group;
static int hf_deribit_ordersapi_order_id;
static int hf_deribit_ordersapi_order_id_fill_id;
static int hf_deribit_ordersapi_order_id_optional;
static int hf_deribit_ordersapi_padding;
static int hf_deribit_ordersapi_padding_3;
static int hf_deribit_ordersapi_post_only;
static int hf_deribit_ordersapi_post_only_reject;
static int hf_deribit_ordersapi_price;
static int hf_deribit_ordersapi_product_type;
static int hf_deribit_ordersapi_protocol_id;
static int hf_deribit_ordersapi_quantity_level;
static int hf_deribit_ordersapi_quote_id;
static int hf_deribit_ordersapi_reason_cancel_order_reject_reason;
static int hf_deribit_ordersapi_reason_data;
static int hf_deribit_ordersapi_reason_length;
static int hf_deribit_ordersapi_reason_mass_cancel_reject_reason;
static int hf_deribit_ordersapi_reason_mass_quote_reject_reason;
static int hf_deribit_ordersapi_reason_mmp_status_reject_reason;
static int hf_deribit_ordersapi_reason_order_reject_reason;
static int hf_deribit_ordersapi_reason_reject_reason;
static int hf_deribit_ordersapi_receive_time;
static int hf_deribit_ordersapi_ref_sequence_number;
static int hf_deribit_ordersapi_reserved_10;
static int hf_deribit_ordersapi_reserved_13;
static int hf_deribit_ordersapi_reserved_6;
static int hf_deribit_ordersapi_reserved_7;
static int hf_deribit_ordersapi_reset_mmp;
static int hf_deribit_ordersapi_reset_seq_num;
static int hf_deribit_ordersapi_schema_version;
static int hf_deribit_ordersapi_secret;
static int hf_deribit_ordersapi_self_match_prevention_id;
static int hf_deribit_ordersapi_self_trading_mode;
static int hf_deribit_ordersapi_send_time_ns;
static int hf_deribit_ordersapi_sequence_number;
static int hf_deribit_ordersapi_session_cancel_on_disconnect;
static int hf_deribit_ordersapi_session_flags;
static int hf_deribit_ordersapi_side;
static int hf_deribit_ordersapi_status;
static int hf_deribit_ordersapi_template_id;
static int hf_deribit_ordersapi_time_in_force;
static int hf_deribit_ordersapi_timestamp;
static int hf_deribit_ordersapi_to_sequence_number;
static int hf_deribit_ordersapi_total_order_count;
static int hf_deribit_ordersapi_trigger;
static int hf_deribit_ordersapi_unused_order_flags_0;
static int hf_deribit_ordersapi_unused_replace_order_flags_0;
static int hf_deribit_ordersapi_vega_level;

/*
 * Deribit OrdersApi Subtrees
 */

static int ett_deribit_ordersapi;
static int ett_deribit_ordersapi_header;
static int ett_deribit_ordersapi_message;
static int ett_deribit_ordersapi_session_flags;
static int ett_deribit_ordersapi_flags_order_flags;
static int ett_deribit_ordersapi_flags_replace_order_flags;
static int ett_deribit_ordersapi_flags_mass_quote_flags;
static int ett_deribit_ordersapi_bid_flags;
static int ett_deribit_ordersapi_ask_flags;
static int ett_deribit_ordersapi_flags_fill_flags;
static int ett_deribit_ordersapi_flags_multi_part_event_flags;
static int ett_deribit_ordersapi_flags_cancel_flags;
static int ett_deribit_ordersapi_flags_order_flags_v10;
static int ett_deribit_ordersapi_bid_flags_v10;
static int ett_deribit_ordersapi_ask_flags_v10;
static int ett_deribit_ordersapi_message_header;
static int ett_deribit_ordersapi_reason;
static int ett_deribit_ordersapi_details;
static int ett_deribit_ordersapi_quantity;
static int ett_deribit_ordersapi_show_qty;
static int ett_deribit_ordersapi_mass_quote_request_message_quotes_groups;
static int ett_deribit_ordersapi_group_size_encoding;
static int ett_deribit_ordersapi_mass_quote_request_message_quotes_group;
static int ett_deribit_ordersapi_bid_qty;
static int ett_deribit_ordersapi_ask_qty;
static int ett_deribit_ordersapi_total_filled;
static int ett_deribit_ordersapi_visible_qty;
static int ett_deribit_ordersapi_new_order_response_message_fills_groups;
static int ett_deribit_ordersapi_new_order_response_message_fills_group;
static int ett_deribit_ordersapi_fill_qty;
static int ett_deribit_ordersapi_new_order_response_message_legs_groups;
static int ett_deribit_ordersapi_new_order_response_message_legs_group;
static int ett_deribit_ordersapi_amend_order_response_message_fills_groups;
static int ett_deribit_ordersapi_amend_order_response_message_fills_group;
static int ett_deribit_ordersapi_amend_order_response_message_legs_groups;
static int ett_deribit_ordersapi_amend_order_response_message_legs_group;
static int ett_deribit_ordersapi_mass_quote_response_message_quotes_groups;
static int ett_deribit_ordersapi_mass_quote_response_message_quotes_group;
static int ett_deribit_ordersapi_bid_filled_qty;
static int ett_deribit_ordersapi_ask_filled_qty;
static int ett_deribit_ordersapi_mass_quote_response_message_bid_fills_groups;
static int ett_deribit_ordersapi_mass_quote_response_message_bid_fills_group;
static int ett_deribit_ordersapi_mass_quote_response_message_ask_fills_groups;
static int ett_deribit_ordersapi_mass_quote_response_message_ask_fills_group;
static int ett_deribit_ordersapi_mass_quote_response_message_legs_groups;
static int ett_deribit_ordersapi_mass_quote_response_message_legs_group;
static int ett_deribit_ordersapi_order_filled_message_fills_groups;
static int ett_deribit_ordersapi_order_filled_message_fills_group;
static int ett_deribit_ordersapi_order_filled_message_legs_groups;
static int ett_deribit_ordersapi_order_filled_message_legs_group;
static int ett_deribit_ordersapi_orders_canceled_message_orders_groups;
static int ett_deribit_ordersapi_orders_canceled_message_orders_group;
static int ett_deribit_ordersapi_order_placed_message_fills_groups;
static int ett_deribit_ordersapi_order_placed_message_fills_group;
static int ett_deribit_ordersapi_order_placed_message_legs_groups;
static int ett_deribit_ordersapi_order_placed_message_legs_group;
static int ett_deribit_ordersapi_mass_quote_orders_placed_message_orders_groups;
static int ett_deribit_ordersapi_mass_quote_orders_placed_message_orders_group;
static int ett_deribit_ordersapi_mass_quote_orders_placed_message_fills_groups;
static int ett_deribit_ordersapi_mass_quote_orders_placed_message_fills_group;
static int ett_deribit_ordersapi_mass_quote_orders_placed_message_legs_groups;
static int ett_deribit_ordersapi_mass_quote_orders_placed_message_legs_group;
static int ett_deribit_ordersapi_mass_quote_request_message_quotes_groups_v10;
static int ett_deribit_ordersapi_mass_quote_request_message_quotes_group_v10;

/*
 * Deribit OrdersApi Expert Information
 */

/* Message length does not account for the parsed fields */
#define DERIBIT_ORDERSAPI_LENGTH_EXPERT_FILTER "deribit.ordersapi.length.invalid"
#define DERIBIT_ORDERSAPI_LENGTH_EXPERT_GROUP PI_MALFORMED
#define DERIBIT_ORDERSAPI_LENGTH_EXPERT_SEVERITY PI_ERROR
#define DERIBIT_ORDERSAPI_LENGTH_EXPERT_SUMMARY "Message length does not account for the parsed fields"

static expert_field ei_deribit_ordersapi_length;

/*
 * Deribit OrdersApi Preferences
 */

#define DERIBIT_ORDERSAPI_VERSION_PREFERENCE_NAME "version"
#define DERIBIT_ORDERSAPI_VERSION_PREFERENCE_TITLE "Protocol version"
#define DERIBIT_ORDERSAPI_VERSION_PREFERENCE_DESCRIPTION "Version used when dissecting, Automatic selects by the packet send time"

#define DERIBIT_ORDERSAPI_VERSION_AUTOMATIC 0
#define DERIBIT_ORDERSAPI_VERSION_1_5     1
#define DERIBIT_ORDERSAPI_VERSION_1_4     2
#define DERIBIT_ORDERSAPI_VERSION_1_3     3
#define DERIBIT_ORDERSAPI_VERSION_1_0     4
#define DERIBIT_ORDERSAPI_VERSION_0_1     5

static const enum_val_t deribit_ordersapi_version_vals[] = {
    { "automatic", "Automatic (by send time)", DERIBIT_ORDERSAPI_VERSION_AUTOMATIC },
    { "v1.5", "1.5", DERIBIT_ORDERSAPI_VERSION_1_5 },
    { "v1.4", "1.4", DERIBIT_ORDERSAPI_VERSION_1_4 },
    { "v1.3", "1.3", DERIBIT_ORDERSAPI_VERSION_1_3 },
    { "v1.0", "1.0", DERIBIT_ORDERSAPI_VERSION_1_0 },
    { "v0.1", "0.1", DERIBIT_ORDERSAPI_VERSION_0_1 },
    { NULL, NULL, 0 }
};

/* The version a frame was read with, for the protocol line */
static const char *
deribit_ordersapi_version_name(int version)
{
    switch (version) {
    case DERIBIT_ORDERSAPI_VERSION_1_5:
        return "1.5";
    case DERIBIT_ORDERSAPI_VERSION_1_4:
        return "1.4";
    case DERIBIT_ORDERSAPI_VERSION_1_3:
        return "1.3";
    case DERIBIT_ORDERSAPI_VERSION_1_0:
        return "1.0";
    case DERIBIT_ORDERSAPI_VERSION_0_1:
        return "0.1";
    }

    return "";
}

static int deribit_ordersapi_pref_version = DERIBIT_ORDERSAPI_VERSION_AUTOMATIC;

/* Version effective times, seconds since the unix epoch */
#define DERIBIT_ORDERSAPI_EFFECTIVE_1_5 UINT64_C(1786060800) /* 2026-08-07 */
#define DERIBIT_ORDERSAPI_EFFECTIVE_1_4 UINT64_C(1785801600) /* 2026-08-04 */
#define DERIBIT_ORDERSAPI_EFFECTIVE_1_3 UINT64_C(1784592000) /* 2026-07-21 */
#define DERIBIT_ORDERSAPI_EFFECTIVE_1_0 UINT64_C(1778025600) /* 2026-05-06 */

/* Show preferences, one per message and struct */
#define DERIBIT_ORDERSAPI_SHOW_HEADERS_PREFERENCE_NAME "show.headers"
#define DERIBIT_ORDERSAPI_SHOW_HEADERS_PREFERENCE_TITLE "Show Headers"
#define DERIBIT_ORDERSAPI_SHOW_HEADERS_PREFERENCE_DESCRIPTION "Show Headers in the protocol tree"

#define DERIBIT_ORDERSAPI_SHOW_APPLICATION_MESSAGES_PREFERENCE_NAME "show.applicationmessages"
#define DERIBIT_ORDERSAPI_SHOW_APPLICATION_MESSAGES_PREFERENCE_TITLE "Show Application Messages"
#define DERIBIT_ORDERSAPI_SHOW_APPLICATION_MESSAGES_PREFERENCE_DESCRIPTION "Show Application Messages in the protocol tree"

#define DERIBIT_ORDERSAPI_SHOW_STRUCTS_PREFERENCE_NAME "show.structs"
#define DERIBIT_ORDERSAPI_SHOW_STRUCTS_PREFERENCE_TITLE "Show Structs"
#define DERIBIT_ORDERSAPI_SHOW_STRUCTS_PREFERENCE_DESCRIPTION "Show Structs in the protocol tree"

static bool deribit_ordersapi_show_headers = true;
static bool deribit_ordersapi_show_application_messages = true;
static bool deribit_ordersapi_show_structs = true;

/* Decimal places shown, the wire precision by default */
#define DERIBIT_ORDERSAPI_DECIMAL_PREFERENCE_NAME "decimal.places"
#define DERIBIT_ORDERSAPI_DECIMAL_PREFERENCE_TITLE "Decimal places"
#define DERIBIT_ORDERSAPI_DECIMAL_PREFERENCE_DESCRIPTION "Decimal places shown for scaled fields, the default is the full wire precision"

static unsigned deribit_ordersapi_pref_decimal_places = 9;

/* Entries of a repeating group are numbered */
#define DERIBIT_ORDERSAPI_INDEXES_PREFERENCE_NAME "show.indexes"
#define DERIBIT_ORDERSAPI_INDEXES_PREFERENCE_TITLE "Show Indexes"
#define DERIBIT_ORDERSAPI_INDEXES_PREFERENCE_DESCRIPTION "Number the entries of a repeating group in the protocol tree"

static bool deribit_ordersapi_pref_show_indexes = true;

/* Ports the feed arrives on, assigned per deployment */
#define DERIBIT_ORDERSAPI_PORTS_PREFERENCE_NAME "ports"
#define DERIBIT_ORDERSAPI_PORTS_PREFERENCE_TITLE "Ports"
#define DERIBIT_ORDERSAPI_PORTS_PREFERENCE_DESCRIPTION "Ports this feed arrives on, set to the ports the exchange assigned this deployment"
#define DERIBIT_ORDERSAPI_PORTS_PREFERENCE_DEFAULT "4210,4211,4212,4213,4214"
#define DERIBIT_ORDERSAPI_PORTS_PREFERENCE_MAXIMUM 65535

static range_t *deribit_ordersapi_pref_ports;

/*
 * Deribit OrdersApi Methods
 */

/* Select the protocol version, from the preference, the
   schema the frame declares, or the capture clock in seconds
   since the unix epoch */
static int
deribit_ordersapi_version(uint64_t seconds)
{
    if (deribit_ordersapi_pref_version != DERIBIT_ORDERSAPI_VERSION_AUTOMATIC) {
        return deribit_ordersapi_pref_version;
    }

    if (seconds >= DERIBIT_ORDERSAPI_EFFECTIVE_1_5) {
        return DERIBIT_ORDERSAPI_VERSION_1_5;
    }

    if (seconds >= DERIBIT_ORDERSAPI_EFFECTIVE_1_4) {
        return DERIBIT_ORDERSAPI_VERSION_1_4;
    }

    if (seconds >= DERIBIT_ORDERSAPI_EFFECTIVE_1_3) {
        return DERIBIT_ORDERSAPI_VERSION_1_3;
    }

    if (seconds >= DERIBIT_ORDERSAPI_EFFECTIVE_1_0) {
        return DERIBIT_ORDERSAPI_VERSION_1_0;
    }

    return DERIBIT_ORDERSAPI_VERSION_0_1;
}

/* Cap the fraction at the preferred decimal places */
static void
deribit_ordersapi_decimal_places(char *buf)
{
    char *point = strchr(buf, '.');

    if (point == NULL) {
        return;
    }

    unsigned places = deribit_ordersapi_pref_decimal_places;

    if (places >= strlen(point + 1)) {
        return;
    }

    if (places == 0) {
        *point = '\0';
        return;
    }

    point[1 + places] = '\0';
}

/* Format an implied 9 decimal place value */
static void
deribit_ordersapi_format_decimal_9_64(char *buf, uint64_t raw)
{
    int64_t value = (int64_t)raw;
    int64_t units = value / 1000000000;
    int64_t fraction = value % 1000000000;

    if (fraction < 0) {
        fraction = -fraction;
    }

    if (value < 0 && units == 0) {
        snprintf(buf, ITEM_LABEL_LENGTH, "-0.%09" PRId64, fraction);
    }
    else {
        snprintf(buf, ITEM_LABEL_LENGTH, "%" PRId64 ".%09" PRId64, units, fraction);
    }

    deribit_ordersapi_decimal_places(buf);
}

/* Format an implied 9 decimal place value */
static void
deribit_ordersapi_format_decimal_9_64_nullable(char *buf, uint64_t raw)
{
    int64_t value = (int64_t)raw;

    if (value == INT64_MIN) {
        snprintf(buf, ITEM_LABEL_LENGTH, "%s", "No Value");
        return;
    }
    int64_t units = value / 1000000000;
    int64_t fraction = value % 1000000000;

    if (fraction < 0) {
        fraction = -fraction;
    }

    if (value < 0 && units == 0) {
        snprintf(buf, ITEM_LABEL_LENGTH, "-0.%09" PRId64, fraction);
    }
    else {
        snprintf(buf, ITEM_LABEL_LENGTH, "%" PRId64 ".%09" PRId64, units, fraction);
    }

    deribit_ordersapi_decimal_places(buf);
}

/* Format a nullable integer, the label alone for the sentinel */
static void
deribit_ordersapi_format_nullable_64(char *buf, uint64_t raw)
{
    int64_t value = (int64_t)raw;

    if (value == INT64_MIN) {
        snprintf(buf, ITEM_LABEL_LENGTH, "%s", "No Value");
        return;
    }

    snprintf(buf, ITEM_LABEL_LENGTH, "%" PRId64, value);
}

/*
 * Deribit OrdersApi Fields
 */

/* Ask Order Id */
#define DERIBIT_ORDERSAPI_ASK_ORDER_ID_NAME        "Ask Order Id"
#define DERIBIT_ORDERSAPI_ASK_ORDER_ID_DESCRIPTION "askOrderId"
#define DERIBIT_ORDERSAPI_ASK_ORDER_ID_FIX         1024
#define DERIBIT_ORDERSAPI_ASK_ORDER_ID_FILTER      "deribit.ordersapi.askorderid"
#define DERIBIT_ORDERSAPI_ASK_ORDER_ID_TYPE        FT_INT64
#define DERIBIT_ORDERSAPI_ASK_ORDER_ID_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_ASK_ORDER_ID_MASK        0x0
#define DERIBIT_ORDERSAPI_ASK_ORDER_ID_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_ASK_ORDER_ID_SIZE        8

static unsigned
parse_deribit_ordersapi_ask_order_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_ask_order_id, tvb, offset, DERIBIT_ORDERSAPI_ASK_ORDER_ID_SIZE, DERIBIT_ORDERSAPI_ASK_ORDER_ID_ENCODING);

    return offset + DERIBIT_ORDERSAPI_ASK_ORDER_ID_SIZE;
}

/* Ask Price */
#define DERIBIT_ORDERSAPI_ASK_PRICE_NAME        "Ask Price"
#define DERIBIT_ORDERSAPI_ASK_PRICE_DESCRIPTION "askPrice"
#define DERIBIT_ORDERSAPI_ASK_PRICE_FIX         1040
#define DERIBIT_ORDERSAPI_ASK_PRICE_FILTER      "deribit.ordersapi.askprice"
#define DERIBIT_ORDERSAPI_ASK_PRICE_TYPE        FT_INT64
#define DERIBIT_ORDERSAPI_ASK_PRICE_DISPLAY     BASE_CUSTOM
#define DERIBIT_ORDERSAPI_ASK_PRICE_MASK        0x0
#define DERIBIT_ORDERSAPI_ASK_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_ASK_PRICE_SIZE        8

static unsigned
parse_deribit_ordersapi_ask_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_ask_price, tvb, offset, DERIBIT_ORDERSAPI_ASK_PRICE_SIZE, DERIBIT_ORDERSAPI_ASK_PRICE_ENCODING);

    return offset + DERIBIT_ORDERSAPI_ASK_PRICE_SIZE;
}

/* Ask Price Optional */
#define DERIBIT_ORDERSAPI_ASK_PRICE_OPTIONAL_NAME        "Ask Price Optional"
#define DERIBIT_ORDERSAPI_ASK_PRICE_OPTIONAL_DESCRIPTION "askPrice"
#define DERIBIT_ORDERSAPI_ASK_PRICE_OPTIONAL_FIX         1024
#define DERIBIT_ORDERSAPI_ASK_PRICE_OPTIONAL_FILTER      "deribit.ordersapi.askpriceoptional"
#define DERIBIT_ORDERSAPI_ASK_PRICE_OPTIONAL_TYPE        FT_INT64
#define DERIBIT_ORDERSAPI_ASK_PRICE_OPTIONAL_DISPLAY     BASE_CUSTOM
#define DERIBIT_ORDERSAPI_ASK_PRICE_OPTIONAL_MASK        0x0
#define DERIBIT_ORDERSAPI_ASK_PRICE_OPTIONAL_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_ASK_PRICE_OPTIONAL_SIZE        8

static unsigned
parse_deribit_ordersapi_ask_price_optional(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_ask_price_optional, tvb, offset, DERIBIT_ORDERSAPI_ASK_PRICE_OPTIONAL_SIZE, DERIBIT_ORDERSAPI_ASK_PRICE_OPTIONAL_ENCODING);

    return offset + DERIBIT_ORDERSAPI_ASK_PRICE_OPTIONAL_SIZE;
}

/* Ask Reject Reason */
#define DERIBIT_ORDERSAPI_ASK_REJECT_REASON_NAME        "Ask Reject Reason"
#define DERIBIT_ORDERSAPI_ASK_REJECT_REASON_DESCRIPTION "askRejectReason"
#define DERIBIT_ORDERSAPI_ASK_REJECT_REASON_FIX         1080
#define DERIBIT_ORDERSAPI_ASK_REJECT_REASON_FILTER      "deribit.ordersapi.askrejectreason"
#define DERIBIT_ORDERSAPI_ASK_REJECT_REASON_TYPE        FT_INT8
#define DERIBIT_ORDERSAPI_ASK_REJECT_REASON_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_ASK_REJECT_REASON_MASK        0x0
#define DERIBIT_ORDERSAPI_ASK_REJECT_REASON_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_ASK_REJECT_REASON_SIZE        1

static const value_string deribit_ordersapi_ask_reject_reason_vals[] = {
    { 0, "System Error" },
    { 1, "Invalid Instrument" },
    { 2, "Invalid Field" },
    { 3, "Insufficient Margin" },
    { 4, "Duplicate Client Order Id" },
    { 5, "Invalid Quantity" },
    { 6, "Invalid Price" },
    { 7, "Not Allowed By Market State" },
    { 8, "Post Only" },
    { 9, "Too Many Open Orders" },
    { 10, "Permission Error" },
    { 11, "Portfolio Not Found" },
    { 12, "Order Not Found" },
    { 13, "Mmp Not Configured" },
    { 14, "Mmp Max Quote Qty Exceeded" },
    { 15, "Mmp Group Frozen" },
    { 16, "Invalid Margin Mode" },
    { 17, "In Liquidation" },
    { 18, "Risk Check Timed Out" },
    { 19, "Too Many Pending Replaces" },
    { 20, "Iceberg Not Allowed" },
    { 21, "Invalid Allocations" },
    { 22, "Price Too High" },
    { 23, "Price Too Low" },
    { 24, "Price Band Unavailable" },
    { 25, "Rate Limit" },
    { 26, "Portfolio Locked" },
    { 27, "Position Limit Exceeded" },
    { 28, "Order Size Limit Exceeded" },
    { 29, "Member Speed Bump Limit Exceeded" },
    { 30, "Mmp Min Freeze Time Not Elapsed" },
    { 31, "Cancel Only" },
    { 0, NULL }
};

static unsigned
parse_deribit_ordersapi_ask_reject_reason(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_ask_reject_reason, tvb, offset, DERIBIT_ORDERSAPI_ASK_REJECT_REASON_SIZE, DERIBIT_ORDERSAPI_ASK_REJECT_REASON_ENCODING);

    return offset + DERIBIT_ORDERSAPI_ASK_REJECT_REASON_SIZE;
}

/* Ask Status */
#define DERIBIT_ORDERSAPI_ASK_STATUS_NAME        "Ask Status"
#define DERIBIT_ORDERSAPI_ASK_STATUS_DESCRIPTION "askStatus"
#define DERIBIT_ORDERSAPI_ASK_STATUS_FIX         1078
#define DERIBIT_ORDERSAPI_ASK_STATUS_FILTER      "deribit.ordersapi.askstatus"
#define DERIBIT_ORDERSAPI_ASK_STATUS_TYPE        FT_INT8
#define DERIBIT_ORDERSAPI_ASK_STATUS_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_ASK_STATUS_MASK        0x0
#define DERIBIT_ORDERSAPI_ASK_STATUS_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_ASK_STATUS_SIZE        1

static const value_string deribit_ordersapi_ask_status_vals[] = {
    { 0, "Inactive" },
    { 1, "Unmodified" },
    { 2, "Qty Reduced" },
    { 3, "Updated" },
    { 4, "Filled" },
    { 5, "Canceled By Request" },
    { 6, "Canceled By Mmp" },
    { 7, "Canceled By Self Match" },
    { 8, "Speed Bumped" },
    { 0, NULL }
};

static unsigned
parse_deribit_ordersapi_ask_status(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_ask_status, tvb, offset, DERIBIT_ORDERSAPI_ASK_STATUS_SIZE, DERIBIT_ORDERSAPI_ASK_STATUS_ENCODING);

    return offset + DERIBIT_ORDERSAPI_ASK_STATUS_SIZE;
}

/* Bid Order Id */
#define DERIBIT_ORDERSAPI_BID_ORDER_ID_NAME        "Bid Order Id"
#define DERIBIT_ORDERSAPI_BID_ORDER_ID_DESCRIPTION "bidOrderId"
#define DERIBIT_ORDERSAPI_BID_ORDER_ID_FIX         1016
#define DERIBIT_ORDERSAPI_BID_ORDER_ID_FILTER      "deribit.ordersapi.bidorderid"
#define DERIBIT_ORDERSAPI_BID_ORDER_ID_TYPE        FT_INT64
#define DERIBIT_ORDERSAPI_BID_ORDER_ID_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_BID_ORDER_ID_MASK        0x0
#define DERIBIT_ORDERSAPI_BID_ORDER_ID_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_BID_ORDER_ID_SIZE        8

static unsigned
parse_deribit_ordersapi_bid_order_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_bid_order_id, tvb, offset, DERIBIT_ORDERSAPI_BID_ORDER_ID_SIZE, DERIBIT_ORDERSAPI_BID_ORDER_ID_ENCODING);

    return offset + DERIBIT_ORDERSAPI_BID_ORDER_ID_SIZE;
}

/* Bid Price */
#define DERIBIT_ORDERSAPI_BID_PRICE_NAME        "Bid Price"
#define DERIBIT_ORDERSAPI_BID_PRICE_DESCRIPTION "bidPrice"
#define DERIBIT_ORDERSAPI_BID_PRICE_FIX         1032
#define DERIBIT_ORDERSAPI_BID_PRICE_FILTER      "deribit.ordersapi.bidprice"
#define DERIBIT_ORDERSAPI_BID_PRICE_TYPE        FT_INT64
#define DERIBIT_ORDERSAPI_BID_PRICE_DISPLAY     BASE_CUSTOM
#define DERIBIT_ORDERSAPI_BID_PRICE_MASK        0x0
#define DERIBIT_ORDERSAPI_BID_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_BID_PRICE_SIZE        8

static unsigned
parse_deribit_ordersapi_bid_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_bid_price, tvb, offset, DERIBIT_ORDERSAPI_BID_PRICE_SIZE, DERIBIT_ORDERSAPI_BID_PRICE_ENCODING);

    return offset + DERIBIT_ORDERSAPI_BID_PRICE_SIZE;
}

/* Bid Price Optional */
#define DERIBIT_ORDERSAPI_BID_PRICE_OPTIONAL_NAME        "Bid Price Optional"
#define DERIBIT_ORDERSAPI_BID_PRICE_OPTIONAL_DESCRIPTION "bidPrice"
#define DERIBIT_ORDERSAPI_BID_PRICE_OPTIONAL_FIX         1016
#define DERIBIT_ORDERSAPI_BID_PRICE_OPTIONAL_FILTER      "deribit.ordersapi.bidpriceoptional"
#define DERIBIT_ORDERSAPI_BID_PRICE_OPTIONAL_TYPE        FT_INT64
#define DERIBIT_ORDERSAPI_BID_PRICE_OPTIONAL_DISPLAY     BASE_CUSTOM
#define DERIBIT_ORDERSAPI_BID_PRICE_OPTIONAL_MASK        0x0
#define DERIBIT_ORDERSAPI_BID_PRICE_OPTIONAL_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_BID_PRICE_OPTIONAL_SIZE        8

static unsigned
parse_deribit_ordersapi_bid_price_optional(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_bid_price_optional, tvb, offset, DERIBIT_ORDERSAPI_BID_PRICE_OPTIONAL_SIZE, DERIBIT_ORDERSAPI_BID_PRICE_OPTIONAL_ENCODING);

    return offset + DERIBIT_ORDERSAPI_BID_PRICE_OPTIONAL_SIZE;
}

/* Bid Reject Reason */
#define DERIBIT_ORDERSAPI_BID_REJECT_REASON_NAME        "Bid Reject Reason"
#define DERIBIT_ORDERSAPI_BID_REJECT_REASON_DESCRIPTION "bidRejectReason"
#define DERIBIT_ORDERSAPI_BID_REJECT_REASON_FIX         1079
#define DERIBIT_ORDERSAPI_BID_REJECT_REASON_FILTER      "deribit.ordersapi.bidrejectreason"
#define DERIBIT_ORDERSAPI_BID_REJECT_REASON_TYPE        FT_INT8
#define DERIBIT_ORDERSAPI_BID_REJECT_REASON_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_BID_REJECT_REASON_MASK        0x0
#define DERIBIT_ORDERSAPI_BID_REJECT_REASON_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_BID_REJECT_REASON_SIZE        1

static const value_string deribit_ordersapi_bid_reject_reason_vals[] = {
    { 0, "System Error" },
    { 1, "Invalid Instrument" },
    { 2, "Invalid Field" },
    { 3, "Insufficient Margin" },
    { 4, "Duplicate Client Order Id" },
    { 5, "Invalid Quantity" },
    { 6, "Invalid Price" },
    { 7, "Not Allowed By Market State" },
    { 8, "Post Only" },
    { 9, "Too Many Open Orders" },
    { 10, "Permission Error" },
    { 11, "Portfolio Not Found" },
    { 12, "Order Not Found" },
    { 13, "Mmp Not Configured" },
    { 14, "Mmp Max Quote Qty Exceeded" },
    { 15, "Mmp Group Frozen" },
    { 16, "Invalid Margin Mode" },
    { 17, "In Liquidation" },
    { 18, "Risk Check Timed Out" },
    { 19, "Too Many Pending Replaces" },
    { 20, "Iceberg Not Allowed" },
    { 21, "Invalid Allocations" },
    { 22, "Price Too High" },
    { 23, "Price Too Low" },
    { 24, "Price Band Unavailable" },
    { 25, "Rate Limit" },
    { 26, "Portfolio Locked" },
    { 27, "Position Limit Exceeded" },
    { 28, "Order Size Limit Exceeded" },
    { 29, "Member Speed Bump Limit Exceeded" },
    { 30, "Mmp Min Freeze Time Not Elapsed" },
    { 31, "Cancel Only" },
    { 0, NULL }
};

static unsigned
parse_deribit_ordersapi_bid_reject_reason(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_bid_reject_reason, tvb, offset, DERIBIT_ORDERSAPI_BID_REJECT_REASON_SIZE, DERIBIT_ORDERSAPI_BID_REJECT_REASON_ENCODING);

    return offset + DERIBIT_ORDERSAPI_BID_REJECT_REASON_SIZE;
}

/* Bid Status */
#define DERIBIT_ORDERSAPI_BID_STATUS_NAME        "Bid Status"
#define DERIBIT_ORDERSAPI_BID_STATUS_DESCRIPTION "bidStatus"
#define DERIBIT_ORDERSAPI_BID_STATUS_FIX         1077
#define DERIBIT_ORDERSAPI_BID_STATUS_FILTER      "deribit.ordersapi.bidstatus"
#define DERIBIT_ORDERSAPI_BID_STATUS_TYPE        FT_INT8
#define DERIBIT_ORDERSAPI_BID_STATUS_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_BID_STATUS_MASK        0x0
#define DERIBIT_ORDERSAPI_BID_STATUS_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_BID_STATUS_SIZE        1

static const value_string deribit_ordersapi_bid_status_vals[] = {
    { 0, "Inactive" },
    { 1, "Unmodified" },
    { 2, "Qty Reduced" },
    { 3, "Updated" },
    { 4, "Filled" },
    { 5, "Canceled By Request" },
    { 6, "Canceled By Mmp" },
    { 7, "Canceled By Self Match" },
    { 8, "Speed Bumped" },
    { 0, NULL }
};

static unsigned
parse_deribit_ordersapi_bid_status(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_bid_status, tvb, offset, DERIBIT_ORDERSAPI_BID_STATUS_SIZE, DERIBIT_ORDERSAPI_BID_STATUS_ENCODING);

    return offset + DERIBIT_ORDERSAPI_BID_STATUS_SIZE;
}

/* Block Length */
#define DERIBIT_ORDERSAPI_BLOCK_LENGTH_NAME        "Block Length"
#define DERIBIT_ORDERSAPI_BLOCK_LENGTH_DESCRIPTION "blockLength"
#define DERIBIT_ORDERSAPI_BLOCK_LENGTH_FILTER      "deribit.ordersapi.blocklength"
#define DERIBIT_ORDERSAPI_BLOCK_LENGTH_TYPE        FT_UINT16
#define DERIBIT_ORDERSAPI_BLOCK_LENGTH_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_BLOCK_LENGTH_MASK        0x0
#define DERIBIT_ORDERSAPI_BLOCK_LENGTH_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_BLOCK_LENGTH_SIZE        2

static unsigned
parse_deribit_ordersapi_block_length(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_block_length, tvb, offset, DERIBIT_ORDERSAPI_BLOCK_LENGTH_SIZE, DERIBIT_ORDERSAPI_BLOCK_LENGTH_ENCODING);

    return offset + DERIBIT_ORDERSAPI_BLOCK_LENGTH_SIZE;
}

/* Cancel On Disconnect */
#define DERIBIT_ORDERSAPI_CANCEL_ON_DISCONNECT_NAME        "Cancel On Disconnect"
#define DERIBIT_ORDERSAPI_CANCEL_ON_DISCONNECT_DESCRIPTION "cancelOnDisconnect"
#define DERIBIT_ORDERSAPI_CANCEL_ON_DISCONNECT_FILTER      "deribit.ordersapi.cancelondisconnect"
#define DERIBIT_ORDERSAPI_CANCEL_ON_DISCONNECT_TYPE        FT_BOOLEAN
#define DERIBIT_ORDERSAPI_CANCEL_ON_DISCONNECT_DISPLAY     8
#define DERIBIT_ORDERSAPI_CANCEL_ON_DISCONNECT_MASK        0x01

/* Cancel Reason */
#define DERIBIT_ORDERSAPI_CANCEL_REASON_NAME        "Cancel Reason"
#define DERIBIT_ORDERSAPI_CANCEL_REASON_DESCRIPTION "cancelReason"
#define DERIBIT_ORDERSAPI_CANCEL_REASON_FIX         1034
#define DERIBIT_ORDERSAPI_CANCEL_REASON_FILTER      "deribit.ordersapi.cancelreason"
#define DERIBIT_ORDERSAPI_CANCEL_REASON_TYPE        FT_INT8
#define DERIBIT_ORDERSAPI_CANCEL_REASON_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_CANCEL_REASON_MASK        0x0
#define DERIBIT_ORDERSAPI_CANCEL_REASON_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_CANCEL_REASON_SIZE        1

static const value_string deribit_ordersapi_cancel_reason_vals[] = {
    { 0, "Unknown" },
    { 1, "Self Match Prevention" },
    { 2, "Time In Force" },
    { 3, "Admin" },
    { 4, "Mm Protection" },
    { 5, "Liquidation" },
    { 6, "Market State Transition" },
    { 7, "Client Disconnect" },
    { 8, "Reduce Only" },
    { 9, "Delivered" },
    { 10, "Settlement" },
    { 11, "Book Deactivated" },
    { 12, "By Request" },
    { 13, "Risk Check Timed Out" },
    { 14, "Mmp Group Deleted" },
    { 15, "Portfolio Locked" },
    { 16, "Post Only" },
    { 17, "Qty Tick Size Rescale" },
    { 0, NULL }
};

static unsigned
parse_deribit_ordersapi_cancel_reason(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_cancel_reason, tvb, offset, DERIBIT_ORDERSAPI_CANCEL_REASON_SIZE, DERIBIT_ORDERSAPI_CANCEL_REASON_ENCODING);

    return offset + DERIBIT_ORDERSAPI_CANCEL_REASON_SIZE;
}

/* Client Id */
#define DERIBIT_ORDERSAPI_CLIENT_ID_NAME        "Client Id"
#define DERIBIT_ORDERSAPI_CLIENT_ID_DESCRIPTION "clientId"
#define DERIBIT_ORDERSAPI_CLIENT_ID_FILTER      "deribit.ordersapi.clientid"
#define DERIBIT_ORDERSAPI_CLIENT_ID_TYPE        FT_STRING
#define DERIBIT_ORDERSAPI_CLIENT_ID_DISPLAY     BASE_NONE
#define DERIBIT_ORDERSAPI_CLIENT_ID_MASK        0x0
#define DERIBIT_ORDERSAPI_CLIENT_ID_ENCODING    ENC_ASCII
#define DERIBIT_ORDERSAPI_CLIENT_ID_SIZE        16

static unsigned
parse_deribit_ordersapi_client_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_client_id, tvb, offset, DERIBIT_ORDERSAPI_CLIENT_ID_SIZE, DERIBIT_ORDERSAPI_CLIENT_ID_ENCODING);

    return offset + DERIBIT_ORDERSAPI_CLIENT_ID_SIZE;
}

/* Client Order Id */
#define DERIBIT_ORDERSAPI_CLIENT_ORDER_ID_NAME        "Client Order Id"
#define DERIBIT_ORDERSAPI_CLIENT_ORDER_ID_DESCRIPTION "clientOrderId"
#define DERIBIT_ORDERSAPI_CLIENT_ORDER_ID_FIX         1008
#define DERIBIT_ORDERSAPI_CLIENT_ORDER_ID_FILTER      "deribit.ordersapi.clientorderid"
#define DERIBIT_ORDERSAPI_CLIENT_ORDER_ID_TYPE        FT_INT64
#define DERIBIT_ORDERSAPI_CLIENT_ORDER_ID_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_CLIENT_ORDER_ID_MASK        0x0
#define DERIBIT_ORDERSAPI_CLIENT_ORDER_ID_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_CLIENT_ORDER_ID_SIZE        8

static unsigned
parse_deribit_ordersapi_client_order_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_client_order_id, tvb, offset, DERIBIT_ORDERSAPI_CLIENT_ORDER_ID_SIZE, DERIBIT_ORDERSAPI_CLIENT_ORDER_ID_ENCODING);

    return offset + DERIBIT_ORDERSAPI_CLIENT_ORDER_ID_SIZE;
}

/* Correlation Id */
#define DERIBIT_ORDERSAPI_CORRELATION_ID_NAME        "Correlation Id"
#define DERIBIT_ORDERSAPI_CORRELATION_ID_DESCRIPTION "correlationId"
#define DERIBIT_ORDERSAPI_CORRELATION_ID_FILTER      "deribit.ordersapi.correlationid"
#define DERIBIT_ORDERSAPI_CORRELATION_ID_TYPE        FT_INT64
#define DERIBIT_ORDERSAPI_CORRELATION_ID_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_CORRELATION_ID_MASK        0x0
#define DERIBIT_ORDERSAPI_CORRELATION_ID_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_CORRELATION_ID_SIZE        8

static unsigned
parse_deribit_ordersapi_correlation_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_correlation_id, tvb, offset, DERIBIT_ORDERSAPI_CORRELATION_ID_SIZE, DERIBIT_ORDERSAPI_CORRELATION_ID_ENCODING);

    return offset + DERIBIT_ORDERSAPI_CORRELATION_ID_SIZE;
}

/* Correlation Id Optional */
#define DERIBIT_ORDERSAPI_CORRELATION_ID_OPTIONAL_NAME        "Correlation Id Optional"
#define DERIBIT_ORDERSAPI_CORRELATION_ID_OPTIONAL_DESCRIPTION "correlationId"
#define DERIBIT_ORDERSAPI_CORRELATION_ID_OPTIONAL_FILTER      "deribit.ordersapi.correlationidoptional"
#define DERIBIT_ORDERSAPI_CORRELATION_ID_OPTIONAL_TYPE        FT_INT64
#define DERIBIT_ORDERSAPI_CORRELATION_ID_OPTIONAL_DISPLAY     BASE_CUSTOM
#define DERIBIT_ORDERSAPI_CORRELATION_ID_OPTIONAL_MASK        0x0
#define DERIBIT_ORDERSAPI_CORRELATION_ID_OPTIONAL_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_CORRELATION_ID_OPTIONAL_SIZE        8

static unsigned
parse_deribit_ordersapi_correlation_id_optional(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_correlation_id_optional, tvb, offset, DERIBIT_ORDERSAPI_CORRELATION_ID_OPTIONAL_SIZE, DERIBIT_ORDERSAPI_CORRELATION_ID_OPTIONAL_ENCODING);

    return offset + DERIBIT_ORDERSAPI_CORRELATION_ID_OPTIONAL_SIZE;
}

/* Currency Pair Id */
#define DERIBIT_ORDERSAPI_CURRENCY_PAIR_ID_NAME        "Currency Pair Id"
#define DERIBIT_ORDERSAPI_CURRENCY_PAIR_ID_DESCRIPTION "currencyPairId"
#define DERIBIT_ORDERSAPI_CURRENCY_PAIR_ID_FILTER      "deribit.ordersapi.currencypairid"
#define DERIBIT_ORDERSAPI_CURRENCY_PAIR_ID_TYPE        FT_INT64
#define DERIBIT_ORDERSAPI_CURRENCY_PAIR_ID_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_CURRENCY_PAIR_ID_MASK        0x0
#define DERIBIT_ORDERSAPI_CURRENCY_PAIR_ID_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_CURRENCY_PAIR_ID_SIZE        8

static unsigned
parse_deribit_ordersapi_currency_pair_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_currency_pair_id, tvb, offset, DERIBIT_ORDERSAPI_CURRENCY_PAIR_ID_SIZE, DERIBIT_ORDERSAPI_CURRENCY_PAIR_ID_ENCODING);

    return offset + DERIBIT_ORDERSAPI_CURRENCY_PAIR_ID_SIZE;
}

/* Delta Level */
#define DERIBIT_ORDERSAPI_DELTA_LEVEL_NAME        "Delta Level"
#define DERIBIT_ORDERSAPI_DELTA_LEVEL_DESCRIPTION "deltaLevel"
#define DERIBIT_ORDERSAPI_DELTA_LEVEL_FILTER      "deribit.ordersapi.deltalevel"
#define DERIBIT_ORDERSAPI_DELTA_LEVEL_TYPE        FT_UINT64
#define DERIBIT_ORDERSAPI_DELTA_LEVEL_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_DELTA_LEVEL_MASK        0x0
#define DERIBIT_ORDERSAPI_DELTA_LEVEL_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_DELTA_LEVEL_SIZE        8

static unsigned
parse_deribit_ordersapi_delta_level(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_delta_level, tvb, offset, DERIBIT_ORDERSAPI_DELTA_LEVEL_SIZE, DERIBIT_ORDERSAPI_DELTA_LEVEL_ENCODING);

    return offset + DERIBIT_ORDERSAPI_DELTA_LEVEL_SIZE;
}

/* Details Data */
#define DERIBIT_ORDERSAPI_DETAILS_DATA_NAME     "Details Data"
#define DERIBIT_ORDERSAPI_DETAILS_DATA_FILTER   "deribit.ordersapi.detailsdata"
#define DERIBIT_ORDERSAPI_DETAILS_DATA_TYPE     FT_CHAR
#define DERIBIT_ORDERSAPI_DETAILS_DATA_DISPLAY  BASE_HEX
#define DERIBIT_ORDERSAPI_DETAILS_DATA_MASK     0x0
#define DERIBIT_ORDERSAPI_DETAILS_DATA_ENCODING ENC_ASCII
#define DERIBIT_ORDERSAPI_DETAILS_DATA_SIZE     1

static unsigned
parse_deribit_ordersapi_details_data(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_details_data, tvb, offset, DERIBIT_ORDERSAPI_DETAILS_DATA_SIZE, DERIBIT_ORDERSAPI_DETAILS_DATA_ENCODING);

    return offset + DERIBIT_ORDERSAPI_DETAILS_DATA_SIZE;
}

/* Details Length */
#define DERIBIT_ORDERSAPI_DETAILS_LENGTH_NAME     "Details Length"
#define DERIBIT_ORDERSAPI_DETAILS_LENGTH_FILTER   "deribit.ordersapi.detailslength"
#define DERIBIT_ORDERSAPI_DETAILS_LENGTH_TYPE     FT_UINT8
#define DERIBIT_ORDERSAPI_DETAILS_LENGTH_DISPLAY  BASE_DEC
#define DERIBIT_ORDERSAPI_DETAILS_LENGTH_MASK     0x0
#define DERIBIT_ORDERSAPI_DETAILS_LENGTH_ENCODING ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_DETAILS_LENGTH_SIZE     1

static unsigned
parse_deribit_ordersapi_details_length(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_details_length, tvb, offset, DERIBIT_ORDERSAPI_DETAILS_LENGTH_SIZE, DERIBIT_ORDERSAPI_DETAILS_LENGTH_ENCODING);

    return offset + DERIBIT_ORDERSAPI_DETAILS_LENGTH_SIZE;
}

/* Exec Id */
#define DERIBIT_ORDERSAPI_EXEC_ID_NAME        "Exec Id"
#define DERIBIT_ORDERSAPI_EXEC_ID_DESCRIPTION "execId"
#define DERIBIT_ORDERSAPI_EXEC_ID_FILTER      "deribit.ordersapi.execid"
#define DERIBIT_ORDERSAPI_EXEC_ID_TYPE        FT_INT64
#define DERIBIT_ORDERSAPI_EXEC_ID_DISPLAY     BASE_CUSTOM
#define DERIBIT_ORDERSAPI_EXEC_ID_MASK        0x0
#define DERIBIT_ORDERSAPI_EXEC_ID_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_EXEC_ID_SIZE        8

static unsigned
parse_deribit_ordersapi_exec_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_exec_id, tvb, offset, DERIBIT_ORDERSAPI_EXEC_ID_SIZE, DERIBIT_ORDERSAPI_EXEC_ID_ENCODING);

    return offset + DERIBIT_ORDERSAPI_EXEC_ID_SIZE;
}

/* Exponent */
#define DERIBIT_ORDERSAPI_EXPONENT_NAME     "Exponent"
#define DERIBIT_ORDERSAPI_EXPONENT_FILTER   "deribit.ordersapi.exponent"
#define DERIBIT_ORDERSAPI_EXPONENT_TYPE     FT_INT8
#define DERIBIT_ORDERSAPI_EXPONENT_DISPLAY  BASE_DEC
#define DERIBIT_ORDERSAPI_EXPONENT_MASK     0x0
#define DERIBIT_ORDERSAPI_EXPONENT_ENCODING ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_EXPONENT_SIZE     1

static unsigned
parse_deribit_ordersapi_exponent(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_exponent, tvb, offset, DERIBIT_ORDERSAPI_EXPONENT_SIZE, DERIBIT_ORDERSAPI_EXPONENT_ENCODING);

    return offset + DERIBIT_ORDERSAPI_EXPONENT_SIZE;
}

/* Fill Id */
#define DERIBIT_ORDERSAPI_FILL_ID_NAME        "Fill Id"
#define DERIBIT_ORDERSAPI_FILL_ID_DESCRIPTION "instrumentId"
#define DERIBIT_ORDERSAPI_FILL_ID_FIX         2016
#define DERIBIT_ORDERSAPI_FILL_ID_FILTER      "deribit.ordersapi.fillid"
#define DERIBIT_ORDERSAPI_FILL_ID_TYPE        FT_INT64
#define DERIBIT_ORDERSAPI_FILL_ID_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_FILL_ID_MASK        0x0
#define DERIBIT_ORDERSAPI_FILL_ID_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_FILL_ID_SIZE        8

static unsigned
parse_deribit_ordersapi_fill_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_fill_id, tvb, offset, DERIBIT_ORDERSAPI_FILL_ID_SIZE, DERIBIT_ORDERSAPI_FILL_ID_ENCODING);

    return offset + DERIBIT_ORDERSAPI_FILL_ID_SIZE;
}

/* Fill Price */
#define DERIBIT_ORDERSAPI_FILL_PRICE_NAME        "Fill Price"
#define DERIBIT_ORDERSAPI_FILL_PRICE_DESCRIPTION "fillPrice"
#define DERIBIT_ORDERSAPI_FILL_PRICE_FIX         1016
#define DERIBIT_ORDERSAPI_FILL_PRICE_FILTER      "deribit.ordersapi.fillprice"
#define DERIBIT_ORDERSAPI_FILL_PRICE_TYPE        FT_INT64
#define DERIBIT_ORDERSAPI_FILL_PRICE_DISPLAY     BASE_CUSTOM
#define DERIBIT_ORDERSAPI_FILL_PRICE_MASK        0x0
#define DERIBIT_ORDERSAPI_FILL_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_FILL_PRICE_SIZE        8

static unsigned
parse_deribit_ordersapi_fill_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_fill_price, tvb, offset, DERIBIT_ORDERSAPI_FILL_PRICE_SIZE, DERIBIT_ORDERSAPI_FILL_PRICE_ENCODING);

    return offset + DERIBIT_ORDERSAPI_FILL_PRICE_SIZE;
}

/* From Sequence Number */
#define DERIBIT_ORDERSAPI_FROM_SEQUENCE_NUMBER_NAME        "From Sequence Number"
#define DERIBIT_ORDERSAPI_FROM_SEQUENCE_NUMBER_DESCRIPTION "fromSequenceNumber"
#define DERIBIT_ORDERSAPI_FROM_SEQUENCE_NUMBER_FILTER      "deribit.ordersapi.fromsequencenumber"
#define DERIBIT_ORDERSAPI_FROM_SEQUENCE_NUMBER_TYPE        FT_INT64
#define DERIBIT_ORDERSAPI_FROM_SEQUENCE_NUMBER_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_FROM_SEQUENCE_NUMBER_MASK        0x0
#define DERIBIT_ORDERSAPI_FROM_SEQUENCE_NUMBER_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_FROM_SEQUENCE_NUMBER_SIZE        8

static unsigned
parse_deribit_ordersapi_from_sequence_number(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_from_sequence_number, tvb, offset, DERIBIT_ORDERSAPI_FROM_SEQUENCE_NUMBER_SIZE, DERIBIT_ORDERSAPI_FROM_SEQUENCE_NUMBER_ENCODING);

    return offset + DERIBIT_ORDERSAPI_FROM_SEQUENCE_NUMBER_SIZE;
}

/* Frozen Until */
#define DERIBIT_ORDERSAPI_FROZEN_UNTIL_NAME        "Frozen Until"
#define DERIBIT_ORDERSAPI_FROZEN_UNTIL_DESCRIPTION "frozenUntil"
#define DERIBIT_ORDERSAPI_FROZEN_UNTIL_FILTER      "deribit.ordersapi.frozenuntil"
#define DERIBIT_ORDERSAPI_FROZEN_UNTIL_TYPE        FT_ABSOLUTE_TIME
#define DERIBIT_ORDERSAPI_FROZEN_UNTIL_DISPLAY     ABSOLUTE_TIME_UTC
#define DERIBIT_ORDERSAPI_FROZEN_UNTIL_MASK        0x0
#define DERIBIT_ORDERSAPI_FROZEN_UNTIL_ENCODING    ENC_TIME_NSECS | ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_FROZEN_UNTIL_SIZE        8

static unsigned
parse_deribit_ordersapi_frozen_until(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_frozen_until, tvb, offset, DERIBIT_ORDERSAPI_FROZEN_UNTIL_SIZE, DERIBIT_ORDERSAPI_FROZEN_UNTIL_ENCODING);

    return offset + DERIBIT_ORDERSAPI_FROZEN_UNTIL_SIZE;
}

/* Frozen Until Time */
#define DERIBIT_ORDERSAPI_FROZEN_UNTIL_TIME_NAME        "Frozen Until Time"
#define DERIBIT_ORDERSAPI_FROZEN_UNTIL_TIME_DESCRIPTION "frozenUntilTime"
#define DERIBIT_ORDERSAPI_FROZEN_UNTIL_TIME_FILTER      "deribit.ordersapi.frozenuntiltime"
#define DERIBIT_ORDERSAPI_FROZEN_UNTIL_TIME_TYPE        FT_INT64
#define DERIBIT_ORDERSAPI_FROZEN_UNTIL_TIME_DISPLAY     BASE_CUSTOM
#define DERIBIT_ORDERSAPI_FROZEN_UNTIL_TIME_MASK        0x0
#define DERIBIT_ORDERSAPI_FROZEN_UNTIL_TIME_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_FROZEN_UNTIL_TIME_SIZE        8

static unsigned
parse_deribit_ordersapi_frozen_until_time(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_frozen_until_time, tvb, offset, DERIBIT_ORDERSAPI_FROZEN_UNTIL_TIME_SIZE, DERIBIT_ORDERSAPI_FROZEN_UNTIL_TIME_ENCODING);

    return offset + DERIBIT_ORDERSAPI_FROZEN_UNTIL_TIME_SIZE;
}

/* Heartbeat Interval Seconds */
#define DERIBIT_ORDERSAPI_HEARTBEAT_INTERVAL_SECONDS_NAME        "Heartbeat Interval Seconds"
#define DERIBIT_ORDERSAPI_HEARTBEAT_INTERVAL_SECONDS_DESCRIPTION "heartbeatIntervalSeconds"
#define DERIBIT_ORDERSAPI_HEARTBEAT_INTERVAL_SECONDS_FILTER      "deribit.ordersapi.heartbeatintervalseconds"
#define DERIBIT_ORDERSAPI_HEARTBEAT_INTERVAL_SECONDS_TYPE        FT_INT32
#define DERIBIT_ORDERSAPI_HEARTBEAT_INTERVAL_SECONDS_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_HEARTBEAT_INTERVAL_SECONDS_MASK        0x0
#define DERIBIT_ORDERSAPI_HEARTBEAT_INTERVAL_SECONDS_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_HEARTBEAT_INTERVAL_SECONDS_SIZE        4

static unsigned
parse_deribit_ordersapi_heartbeat_interval_seconds(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_heartbeat_interval_seconds, tvb, offset, DERIBIT_ORDERSAPI_HEARTBEAT_INTERVAL_SECONDS_SIZE, DERIBIT_ORDERSAPI_HEARTBEAT_INTERVAL_SECONDS_ENCODING);

    return offset + DERIBIT_ORDERSAPI_HEARTBEAT_INTERVAL_SECONDS_SIZE;
}

/* Instrument Id */
#define DERIBIT_ORDERSAPI_INSTRUMENT_ID_NAME        "Instrument Id"
#define DERIBIT_ORDERSAPI_INSTRUMENT_ID_DESCRIPTION "instrumentId"
#define DERIBIT_ORDERSAPI_INSTRUMENT_ID_FIX         1008
#define DERIBIT_ORDERSAPI_INSTRUMENT_ID_FILTER      "deribit.ordersapi.instrumentid"
#define DERIBIT_ORDERSAPI_INSTRUMENT_ID_TYPE        FT_INT64
#define DERIBIT_ORDERSAPI_INSTRUMENT_ID_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_INSTRUMENT_ID_MASK        0x0
#define DERIBIT_ORDERSAPI_INSTRUMENT_ID_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_INSTRUMENT_ID_SIZE        8

static unsigned
parse_deribit_ordersapi_instrument_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_instrument_id, tvb, offset, DERIBIT_ORDERSAPI_INSTRUMENT_ID_SIZE, DERIBIT_ORDERSAPI_INSTRUMENT_ID_ENCODING);

    return offset + DERIBIT_ORDERSAPI_INSTRUMENT_ID_SIZE;
}

/* Instrument Id Optional */
#define DERIBIT_ORDERSAPI_INSTRUMENT_ID_OPTIONAL_NAME        "Instrument Id Optional"
#define DERIBIT_ORDERSAPI_INSTRUMENT_ID_OPTIONAL_DESCRIPTION "instrumentId"
#define DERIBIT_ORDERSAPI_INSTRUMENT_ID_OPTIONAL_FILTER      "deribit.ordersapi.instrumentidoptional"
#define DERIBIT_ORDERSAPI_INSTRUMENT_ID_OPTIONAL_TYPE        FT_INT64
#define DERIBIT_ORDERSAPI_INSTRUMENT_ID_OPTIONAL_DISPLAY     BASE_CUSTOM
#define DERIBIT_ORDERSAPI_INSTRUMENT_ID_OPTIONAL_MASK        0x0
#define DERIBIT_ORDERSAPI_INSTRUMENT_ID_OPTIONAL_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_INSTRUMENT_ID_OPTIONAL_SIZE        8

static unsigned
parse_deribit_ordersapi_instrument_id_optional(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_instrument_id_optional, tvb, offset, DERIBIT_ORDERSAPI_INSTRUMENT_ID_OPTIONAL_SIZE, DERIBIT_ORDERSAPI_INSTRUMENT_ID_OPTIONAL_ENCODING);

    return offset + DERIBIT_ORDERSAPI_INSTRUMENT_ID_OPTIONAL_SIZE;
}

/* Is Fully Filled */
#define DERIBIT_ORDERSAPI_IS_FULLY_FILLED_NAME        "Is Fully Filled"
#define DERIBIT_ORDERSAPI_IS_FULLY_FILLED_DESCRIPTION "isFullyFilled"
#define DERIBIT_ORDERSAPI_IS_FULLY_FILLED_FILTER      "deribit.ordersapi.isfullyfilled"
#define DERIBIT_ORDERSAPI_IS_FULLY_FILLED_TYPE        FT_BOOLEAN
#define DERIBIT_ORDERSAPI_IS_FULLY_FILLED_DISPLAY     8
#define DERIBIT_ORDERSAPI_IS_FULLY_FILLED_MASK        0x02

/* Is Last Message */
#define DERIBIT_ORDERSAPI_IS_LAST_MESSAGE_NAME        "Is Last Message"
#define DERIBIT_ORDERSAPI_IS_LAST_MESSAGE_DESCRIPTION "isLastMessage"
#define DERIBIT_ORDERSAPI_IS_LAST_MESSAGE_FILTER      "deribit.ordersapi.islastmessage"
#define DERIBIT_ORDERSAPI_IS_LAST_MESSAGE_TYPE        FT_BOOLEAN
#define DERIBIT_ORDERSAPI_IS_LAST_MESSAGE_DISPLAY     8
#define DERIBIT_ORDERSAPI_IS_LAST_MESSAGE_MASK        0x01

/* Is Quote */
#define DERIBIT_ORDERSAPI_IS_QUOTE_NAME        "Is Quote"
#define DERIBIT_ORDERSAPI_IS_QUOTE_DESCRIPTION "isQuote"
#define DERIBIT_ORDERSAPI_IS_QUOTE_FILTER      "deribit.ordersapi.isquote"
#define DERIBIT_ORDERSAPI_IS_QUOTE_TYPE        FT_BOOLEAN
#define DERIBIT_ORDERSAPI_IS_QUOTE_DISPLAY     8
#define DERIBIT_ORDERSAPI_IS_QUOTE_MASK        0x01

/* Is Resend */
#define DERIBIT_ORDERSAPI_IS_RESEND_NAME        "Is Resend"
#define DERIBIT_ORDERSAPI_IS_RESEND_DESCRIPTION "Possibly resent message indicator"
#define DERIBIT_ORDERSAPI_IS_RESEND_FILTER      "deribit.ordersapi.isresend"
#define DERIBIT_ORDERSAPI_IS_RESEND_TYPE        FT_BOOLEAN
#define DERIBIT_ORDERSAPI_IS_RESEND_DISPLAY     8
#define DERIBIT_ORDERSAPI_IS_RESEND_MASK        0x01

/* Last Processed Seq No */
#define DERIBIT_ORDERSAPI_LAST_PROCESSED_SEQ_NO_NAME        "Last Processed Seq No"
#define DERIBIT_ORDERSAPI_LAST_PROCESSED_SEQ_NO_DESCRIPTION "Highest sequence number the sender has processed from the counterparty"
#define DERIBIT_ORDERSAPI_LAST_PROCESSED_SEQ_NO_FILTER      "deribit.ordersapi.lastprocessedseqno"
#define DERIBIT_ORDERSAPI_LAST_PROCESSED_SEQ_NO_TYPE        FT_INT64
#define DERIBIT_ORDERSAPI_LAST_PROCESSED_SEQ_NO_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_LAST_PROCESSED_SEQ_NO_MASK        0x0
#define DERIBIT_ORDERSAPI_LAST_PROCESSED_SEQ_NO_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_LAST_PROCESSED_SEQ_NO_SIZE        8

static unsigned
parse_deribit_ordersapi_last_processed_seq_no(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_last_processed_seq_no, tvb, offset, DERIBIT_ORDERSAPI_LAST_PROCESSED_SEQ_NO_SIZE, DERIBIT_ORDERSAPI_LAST_PROCESSED_SEQ_NO_ENCODING);

    return offset + DERIBIT_ORDERSAPI_LAST_PROCESSED_SEQ_NO_SIZE;
}

/* Leg Side */
#define DERIBIT_ORDERSAPI_LEG_SIDE_NAME        "Leg Side"
#define DERIBIT_ORDERSAPI_LEG_SIDE_DESCRIPTION "legSide"
#define DERIBIT_ORDERSAPI_LEG_SIDE_FIX         2034
#define DERIBIT_ORDERSAPI_LEG_SIDE_FILTER      "deribit.ordersapi.legside"
#define DERIBIT_ORDERSAPI_LEG_SIDE_TYPE        FT_INT8
#define DERIBIT_ORDERSAPI_LEG_SIDE_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_LEG_SIDE_MASK        0x0
#define DERIBIT_ORDERSAPI_LEG_SIDE_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_LEG_SIDE_SIZE        1

static const value_string deribit_ordersapi_leg_side_vals[] = {
    { 1, "Buy" },
    { 0, "Both" },
    { -1, "Sell" },
    { 0, NULL }
};

static unsigned
parse_deribit_ordersapi_leg_side(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_leg_side, tvb, offset, DERIBIT_ORDERSAPI_LEG_SIDE_SIZE, DERIBIT_ORDERSAPI_LEG_SIDE_ENCODING);

    return offset + DERIBIT_ORDERSAPI_LEG_SIDE_SIZE;
}

/* Mantissa */
#define DERIBIT_ORDERSAPI_MANTISSA_NAME     "Mantissa"
#define DERIBIT_ORDERSAPI_MANTISSA_FILTER   "deribit.ordersapi.mantissa"
#define DERIBIT_ORDERSAPI_MANTISSA_TYPE     FT_INT64
#define DERIBIT_ORDERSAPI_MANTISSA_DISPLAY  BASE_DEC
#define DERIBIT_ORDERSAPI_MANTISSA_MASK     0x0
#define DERIBIT_ORDERSAPI_MANTISSA_ENCODING ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_MANTISSA_SIZE     8

static unsigned
parse_deribit_ordersapi_mantissa(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_mantissa, tvb, offset, DERIBIT_ORDERSAPI_MANTISSA_SIZE, DERIBIT_ORDERSAPI_MANTISSA_ENCODING);

    return offset + DERIBIT_ORDERSAPI_MANTISSA_SIZE;
}

/* Market Limit */
#define DERIBIT_ORDERSAPI_MARKET_LIMIT_NAME        "Market Limit"
#define DERIBIT_ORDERSAPI_MARKET_LIMIT_DESCRIPTION "marketLimit"
#define DERIBIT_ORDERSAPI_MARKET_LIMIT_FILTER      "deribit.ordersapi.marketlimit"
#define DERIBIT_ORDERSAPI_MARKET_LIMIT_TYPE        FT_BOOLEAN
#define DERIBIT_ORDERSAPI_MARKET_LIMIT_DISPLAY     8
#define DERIBIT_ORDERSAPI_MARKET_LIMIT_MASK        0x08

/* Match Id */
#define DERIBIT_ORDERSAPI_MATCH_ID_NAME        "Match Id"
#define DERIBIT_ORDERSAPI_MATCH_ID_DESCRIPTION "matchId"
#define DERIBIT_ORDERSAPI_MATCH_ID_FIX         1008
#define DERIBIT_ORDERSAPI_MATCH_ID_FILTER      "deribit.ordersapi.matchid"
#define DERIBIT_ORDERSAPI_MATCH_ID_TYPE        FT_INT64
#define DERIBIT_ORDERSAPI_MATCH_ID_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_MATCH_ID_MASK        0x0
#define DERIBIT_ORDERSAPI_MATCH_ID_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_MATCH_ID_SIZE        8

static unsigned
parse_deribit_ordersapi_match_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_match_id, tvb, offset, DERIBIT_ORDERSAPI_MATCH_ID_SIZE, DERIBIT_ORDERSAPI_MATCH_ID_ENCODING);

    return offset + DERIBIT_ORDERSAPI_MATCH_ID_SIZE;
}

/* Message Length */
#define DERIBIT_ORDERSAPI_MESSAGE_LENGTH_NAME        "Message Length"
#define DERIBIT_ORDERSAPI_MESSAGE_LENGTH_DESCRIPTION "Total message length in bytes including this header"
#define DERIBIT_ORDERSAPI_MESSAGE_LENGTH_FILTER      "deribit.ordersapi.messagelength"
#define DERIBIT_ORDERSAPI_MESSAGE_LENGTH_TYPE        FT_UINT16
#define DERIBIT_ORDERSAPI_MESSAGE_LENGTH_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_MESSAGE_LENGTH_MASK        0x0
#define DERIBIT_ORDERSAPI_MESSAGE_LENGTH_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_MESSAGE_LENGTH_SIZE        2

static unsigned
parse_deribit_ordersapi_message_length(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_message_length, tvb, offset, DERIBIT_ORDERSAPI_MESSAGE_LENGTH_SIZE, DERIBIT_ORDERSAPI_MESSAGE_LENGTH_ENCODING);

    return offset + DERIBIT_ORDERSAPI_MESSAGE_LENGTH_SIZE;
}

/* Mmp */
#define DERIBIT_ORDERSAPI_MMP_NAME    "Mmp"
#define DERIBIT_ORDERSAPI_MMP_FILTER  "deribit.ordersapi.mmp"
#define DERIBIT_ORDERSAPI_MMP_TYPE    FT_BOOLEAN
#define DERIBIT_ORDERSAPI_MMP_DISPLAY 8
#define DERIBIT_ORDERSAPI_MMP_MASK    0x10

/* Mmp Group Id */
#define DERIBIT_ORDERSAPI_MMP_GROUP_ID_NAME        "Mmp Group Id"
#define DERIBIT_ORDERSAPI_MMP_GROUP_ID_DESCRIPTION "mmpGroupId"
#define DERIBIT_ORDERSAPI_MMP_GROUP_ID_FILTER      "deribit.ordersapi.mmpgroupid"
#define DERIBIT_ORDERSAPI_MMP_GROUP_ID_TYPE        FT_INT64
#define DERIBIT_ORDERSAPI_MMP_GROUP_ID_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_MMP_GROUP_ID_MASK        0x0
#define DERIBIT_ORDERSAPI_MMP_GROUP_ID_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_MMP_GROUP_ID_SIZE        8

static unsigned
parse_deribit_ordersapi_mmp_group_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_mmp_group_id, tvb, offset, DERIBIT_ORDERSAPI_MMP_GROUP_ID_SIZE, DERIBIT_ORDERSAPI_MMP_GROUP_ID_ENCODING);

    return offset + DERIBIT_ORDERSAPI_MMP_GROUP_ID_SIZE;
}

/* New Sequence Number */
#define DERIBIT_ORDERSAPI_NEW_SEQUENCE_NUMBER_NAME        "New Sequence Number"
#define DERIBIT_ORDERSAPI_NEW_SEQUENCE_NUMBER_DESCRIPTION "newSequenceNumber"
#define DERIBIT_ORDERSAPI_NEW_SEQUENCE_NUMBER_FILTER      "deribit.ordersapi.newsequencenumber"
#define DERIBIT_ORDERSAPI_NEW_SEQUENCE_NUMBER_TYPE        FT_INT64
#define DERIBIT_ORDERSAPI_NEW_SEQUENCE_NUMBER_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_NEW_SEQUENCE_NUMBER_MASK        0x0
#define DERIBIT_ORDERSAPI_NEW_SEQUENCE_NUMBER_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_NEW_SEQUENCE_NUMBER_SIZE        8

static unsigned
parse_deribit_ordersapi_new_sequence_number(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_new_sequence_number, tvb, offset, DERIBIT_ORDERSAPI_NEW_SEQUENCE_NUMBER_SIZE, DERIBIT_ORDERSAPI_NEW_SEQUENCE_NUMBER_ENCODING);

    return offset + DERIBIT_ORDERSAPI_NEW_SEQUENCE_NUMBER_SIZE;
}

/* Num In Group */
#define DERIBIT_ORDERSAPI_NUM_IN_GROUP_NAME        "Num In Group"
#define DERIBIT_ORDERSAPI_NUM_IN_GROUP_DESCRIPTION "numInGroup"
#define DERIBIT_ORDERSAPI_NUM_IN_GROUP_FILTER      "deribit.ordersapi.numingroup"
#define DERIBIT_ORDERSAPI_NUM_IN_GROUP_TYPE        FT_UINT16
#define DERIBIT_ORDERSAPI_NUM_IN_GROUP_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_NUM_IN_GROUP_MASK        0x0
#define DERIBIT_ORDERSAPI_NUM_IN_GROUP_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_NUM_IN_GROUP_SIZE        2

static unsigned
parse_deribit_ordersapi_num_in_group(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_num_in_group, tvb, offset, DERIBIT_ORDERSAPI_NUM_IN_GROUP_SIZE, DERIBIT_ORDERSAPI_NUM_IN_GROUP_ENCODING);

    return offset + DERIBIT_ORDERSAPI_NUM_IN_GROUP_SIZE;
}

/* Order Id */
#define DERIBIT_ORDERSAPI_ORDER_ID_NAME        "Order Id"
#define DERIBIT_ORDERSAPI_ORDER_ID_DESCRIPTION "orderId"
#define DERIBIT_ORDERSAPI_ORDER_ID_FIX         1016
#define DERIBIT_ORDERSAPI_ORDER_ID_FILTER      "deribit.ordersapi.orderid"
#define DERIBIT_ORDERSAPI_ORDER_ID_TYPE        FT_INT64
#define DERIBIT_ORDERSAPI_ORDER_ID_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_ORDER_ID_MASK        0x0
#define DERIBIT_ORDERSAPI_ORDER_ID_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_ORDER_ID_SIZE        8

static unsigned
parse_deribit_ordersapi_order_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_order_id, tvb, offset, DERIBIT_ORDERSAPI_ORDER_ID_SIZE, DERIBIT_ORDERSAPI_ORDER_ID_ENCODING);

    return offset + DERIBIT_ORDERSAPI_ORDER_ID_SIZE;
}

/* Order Id Fill Id */
#define DERIBIT_ORDERSAPI_ORDER_ID_FILL_ID_NAME        "Order Id Fill Id"
#define DERIBIT_ORDERSAPI_ORDER_ID_FILL_ID_DESCRIPTION "orderId"
#define DERIBIT_ORDERSAPI_ORDER_ID_FILL_ID_FIX         2016
#define DERIBIT_ORDERSAPI_ORDER_ID_FILL_ID_FILTER      "deribit.ordersapi.orderidfillid"
#define DERIBIT_ORDERSAPI_ORDER_ID_FILL_ID_TYPE        FT_INT64
#define DERIBIT_ORDERSAPI_ORDER_ID_FILL_ID_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_ORDER_ID_FILL_ID_MASK        0x0
#define DERIBIT_ORDERSAPI_ORDER_ID_FILL_ID_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_ORDER_ID_FILL_ID_SIZE        8

static unsigned
parse_deribit_ordersapi_order_id_fill_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_order_id_fill_id, tvb, offset, DERIBIT_ORDERSAPI_ORDER_ID_FILL_ID_SIZE, DERIBIT_ORDERSAPI_ORDER_ID_FILL_ID_ENCODING);

    return offset + DERIBIT_ORDERSAPI_ORDER_ID_FILL_ID_SIZE;
}

/* Order Id Optional */
#define DERIBIT_ORDERSAPI_ORDER_ID_OPTIONAL_NAME        "Order Id Optional"
#define DERIBIT_ORDERSAPI_ORDER_ID_OPTIONAL_DESCRIPTION "orderId"
#define DERIBIT_ORDERSAPI_ORDER_ID_OPTIONAL_FILTER      "deribit.ordersapi.orderidoptional"
#define DERIBIT_ORDERSAPI_ORDER_ID_OPTIONAL_TYPE        FT_INT64
#define DERIBIT_ORDERSAPI_ORDER_ID_OPTIONAL_DISPLAY     BASE_CUSTOM
#define DERIBIT_ORDERSAPI_ORDER_ID_OPTIONAL_MASK        0x0
#define DERIBIT_ORDERSAPI_ORDER_ID_OPTIONAL_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_ORDER_ID_OPTIONAL_SIZE        8

static unsigned
parse_deribit_ordersapi_order_id_optional(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_order_id_optional, tvb, offset, DERIBIT_ORDERSAPI_ORDER_ID_OPTIONAL_SIZE, DERIBIT_ORDERSAPI_ORDER_ID_OPTIONAL_ENCODING);

    return offset + DERIBIT_ORDERSAPI_ORDER_ID_OPTIONAL_SIZE;
}

/* Padding */
#define DERIBIT_ORDERSAPI_PADDING_NAME        "Padding"
#define DERIBIT_ORDERSAPI_PADDING_DESCRIPTION "Tcp sbe alignment padding"
#define DERIBIT_ORDERSAPI_PADDING_FILTER      "deribit.ordersapi.padding"
#define DERIBIT_ORDERSAPI_PADDING_TYPE        FT_BYTES
#define DERIBIT_ORDERSAPI_PADDING_DISPLAY     BASE_NONE
#define DERIBIT_ORDERSAPI_PADDING_MASK        0x0
#define DERIBIT_ORDERSAPI_PADDING_ENCODING    ENC_NA

/* Padding 3 */
#define DERIBIT_ORDERSAPI_PADDING_3_NAME        "Padding 3"
#define DERIBIT_ORDERSAPI_PADDING_3_DESCRIPTION "padding3"
#define DERIBIT_ORDERSAPI_PADDING_3_FILTER      "deribit.ordersapi.padding3"
#define DERIBIT_ORDERSAPI_PADDING_3_TYPE        FT_INT24
#define DERIBIT_ORDERSAPI_PADDING_3_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_PADDING_3_MASK        0x0
#define DERIBIT_ORDERSAPI_PADDING_3_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_PADDING_3_SIZE        3

static unsigned
parse_deribit_ordersapi_padding_3(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_padding_3, tvb, offset, DERIBIT_ORDERSAPI_PADDING_3_SIZE, DERIBIT_ORDERSAPI_PADDING_3_ENCODING);

    return offset + DERIBIT_ORDERSAPI_PADDING_3_SIZE;
}

/* Post Only */
#define DERIBIT_ORDERSAPI_POST_ONLY_NAME        "Post Only"
#define DERIBIT_ORDERSAPI_POST_ONLY_DESCRIPTION "postOnly"
#define DERIBIT_ORDERSAPI_POST_ONLY_FILTER      "deribit.ordersapi.postonly"
#define DERIBIT_ORDERSAPI_POST_ONLY_TYPE        FT_BOOLEAN
#define DERIBIT_ORDERSAPI_POST_ONLY_DISPLAY     8
#define DERIBIT_ORDERSAPI_POST_ONLY_MASK        0x02

/* Post Only Reject */
#define DERIBIT_ORDERSAPI_POST_ONLY_REJECT_NAME        "Post Only Reject"
#define DERIBIT_ORDERSAPI_POST_ONLY_REJECT_DESCRIPTION "postOnlyReject"
#define DERIBIT_ORDERSAPI_POST_ONLY_REJECT_FILTER      "deribit.ordersapi.postonlyreject"
#define DERIBIT_ORDERSAPI_POST_ONLY_REJECT_TYPE        FT_BOOLEAN
#define DERIBIT_ORDERSAPI_POST_ONLY_REJECT_DISPLAY     8
#define DERIBIT_ORDERSAPI_POST_ONLY_REJECT_MASK        0x04

/* Price */
#define DERIBIT_ORDERSAPI_PRICE_NAME     "Price"
#define DERIBIT_ORDERSAPI_PRICE_FIX      1040
#define DERIBIT_ORDERSAPI_PRICE_FILTER   "deribit.ordersapi.price"
#define DERIBIT_ORDERSAPI_PRICE_TYPE     FT_INT64
#define DERIBIT_ORDERSAPI_PRICE_DISPLAY  BASE_CUSTOM
#define DERIBIT_ORDERSAPI_PRICE_MASK     0x0
#define DERIBIT_ORDERSAPI_PRICE_ENCODING ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_PRICE_SIZE     8

static unsigned
parse_deribit_ordersapi_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_price, tvb, offset, DERIBIT_ORDERSAPI_PRICE_SIZE, DERIBIT_ORDERSAPI_PRICE_ENCODING);

    return offset + DERIBIT_ORDERSAPI_PRICE_SIZE;
}

/* Product Type */
#define DERIBIT_ORDERSAPI_PRODUCT_TYPE_NAME        "Product Type"
#define DERIBIT_ORDERSAPI_PRODUCT_TYPE_DESCRIPTION "productType"
#define DERIBIT_ORDERSAPI_PRODUCT_TYPE_FILTER      "deribit.ordersapi.producttype"
#define DERIBIT_ORDERSAPI_PRODUCT_TYPE_TYPE        FT_INT8
#define DERIBIT_ORDERSAPI_PRODUCT_TYPE_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_PRODUCT_TYPE_MASK        0x0
#define DERIBIT_ORDERSAPI_PRODUCT_TYPE_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_PRODUCT_TYPE_SIZE        1

static const value_string deribit_ordersapi_product_type_vals[] = {
    { 0, "All" },
    { 1, "Options" },
    { 2, "Futures" },
    { 3, "Combo Futures" },
    { 4, "Combo Options" },
    { 5, "Spot" },
    { 0, NULL }
};

static unsigned
parse_deribit_ordersapi_product_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_product_type, tvb, offset, DERIBIT_ORDERSAPI_PRODUCT_TYPE_SIZE, DERIBIT_ORDERSAPI_PRODUCT_TYPE_ENCODING);

    return offset + DERIBIT_ORDERSAPI_PRODUCT_TYPE_SIZE;
}

/* Protocol Id */
#define DERIBIT_ORDERSAPI_PROTOCOL_ID_NAME        "Protocol Id"
#define DERIBIT_ORDERSAPI_PROTOCOL_ID_DESCRIPTION "Coinbase Deribit protocol identifier"
#define DERIBIT_ORDERSAPI_PROTOCOL_ID_FILTER      "deribit.ordersapi.protocolid"
#define DERIBIT_ORDERSAPI_PROTOCOL_ID_TYPE        FT_UINT8
#define DERIBIT_ORDERSAPI_PROTOCOL_ID_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_PROTOCOL_ID_MASK        0x0
#define DERIBIT_ORDERSAPI_PROTOCOL_ID_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_PROTOCOL_ID_SIZE        1

static unsigned
parse_deribit_ordersapi_protocol_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_protocol_id, tvb, offset, DERIBIT_ORDERSAPI_PROTOCOL_ID_SIZE, DERIBIT_ORDERSAPI_PROTOCOL_ID_ENCODING);

    return offset + DERIBIT_ORDERSAPI_PROTOCOL_ID_SIZE;
}

/* Quantity Level */
#define DERIBIT_ORDERSAPI_QUANTITY_LEVEL_NAME        "Quantity Level"
#define DERIBIT_ORDERSAPI_QUANTITY_LEVEL_DESCRIPTION "quantityLevel"
#define DERIBIT_ORDERSAPI_QUANTITY_LEVEL_FILTER      "deribit.ordersapi.quantitylevel"
#define DERIBIT_ORDERSAPI_QUANTITY_LEVEL_TYPE        FT_UINT64
#define DERIBIT_ORDERSAPI_QUANTITY_LEVEL_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_QUANTITY_LEVEL_MASK        0x0
#define DERIBIT_ORDERSAPI_QUANTITY_LEVEL_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_QUANTITY_LEVEL_SIZE        8

static unsigned
parse_deribit_ordersapi_quantity_level(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_quantity_level, tvb, offset, DERIBIT_ORDERSAPI_QUANTITY_LEVEL_SIZE, DERIBIT_ORDERSAPI_QUANTITY_LEVEL_ENCODING);

    return offset + DERIBIT_ORDERSAPI_QUANTITY_LEVEL_SIZE;
}

/* Quote Id */
#define DERIBIT_ORDERSAPI_QUOTE_ID_NAME        "Quote Id"
#define DERIBIT_ORDERSAPI_QUOTE_ID_DESCRIPTION "quoteId"
#define DERIBIT_ORDERSAPI_QUOTE_ID_FILTER      "deribit.ordersapi.quoteid"
#define DERIBIT_ORDERSAPI_QUOTE_ID_TYPE        FT_INT64
#define DERIBIT_ORDERSAPI_QUOTE_ID_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_QUOTE_ID_MASK        0x0
#define DERIBIT_ORDERSAPI_QUOTE_ID_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_QUOTE_ID_SIZE        8

static unsigned
parse_deribit_ordersapi_quote_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_quote_id, tvb, offset, DERIBIT_ORDERSAPI_QUOTE_ID_SIZE, DERIBIT_ORDERSAPI_QUOTE_ID_ENCODING);

    return offset + DERIBIT_ORDERSAPI_QUOTE_ID_SIZE;
}

/* Reason Cancel Order Reject Reason */
#define DERIBIT_ORDERSAPI_REASON_CANCEL_ORDER_REJECT_REASON_NAME        "Reason Cancel Order Reject Reason"
#define DERIBIT_ORDERSAPI_REASON_CANCEL_ORDER_REJECT_REASON_DESCRIPTION "reason"
#define DERIBIT_ORDERSAPI_REASON_CANCEL_ORDER_REJECT_REASON_FILTER      "deribit.ordersapi.reasoncancelorderrejectreason"
#define DERIBIT_ORDERSAPI_REASON_CANCEL_ORDER_REJECT_REASON_TYPE        FT_INT8
#define DERIBIT_ORDERSAPI_REASON_CANCEL_ORDER_REJECT_REASON_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_REASON_CANCEL_ORDER_REJECT_REASON_MASK        0x0
#define DERIBIT_ORDERSAPI_REASON_CANCEL_ORDER_REJECT_REASON_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_REASON_CANCEL_ORDER_REJECT_REASON_SIZE        1

static const value_string deribit_ordersapi_reason_cancel_order_reject_reason_vals[] = {
    { 0, "Error" },
    { 1, "Unknown Order" },
    { 2, "Client Permission Error" },
    { 3, "Not Allowed By Market State" },
    { 4, "Cancel Pending" },
    { 5, "In Liquidation" },
    { 6, "Invalid Instrument" },
    { 7, "Time In Force" },
    { 8, "Speed Bump Converted To Ioc" },
    { 0, NULL }
};

static unsigned
parse_deribit_ordersapi_reason_cancel_order_reject_reason(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_reason_cancel_order_reject_reason, tvb, offset, DERIBIT_ORDERSAPI_REASON_CANCEL_ORDER_REJECT_REASON_SIZE, DERIBIT_ORDERSAPI_REASON_CANCEL_ORDER_REJECT_REASON_ENCODING);

    return offset + DERIBIT_ORDERSAPI_REASON_CANCEL_ORDER_REJECT_REASON_SIZE;
}

/* Reason Data */
#define DERIBIT_ORDERSAPI_REASON_DATA_NAME     "Reason Data"
#define DERIBIT_ORDERSAPI_REASON_DATA_FILTER   "deribit.ordersapi.reasondata"
#define DERIBIT_ORDERSAPI_REASON_DATA_TYPE     FT_CHAR
#define DERIBIT_ORDERSAPI_REASON_DATA_DISPLAY  BASE_HEX
#define DERIBIT_ORDERSAPI_REASON_DATA_MASK     0x0
#define DERIBIT_ORDERSAPI_REASON_DATA_ENCODING ENC_ASCII
#define DERIBIT_ORDERSAPI_REASON_DATA_SIZE     1

static unsigned
parse_deribit_ordersapi_reason_data(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_reason_data, tvb, offset, DERIBIT_ORDERSAPI_REASON_DATA_SIZE, DERIBIT_ORDERSAPI_REASON_DATA_ENCODING);

    return offset + DERIBIT_ORDERSAPI_REASON_DATA_SIZE;
}

/* Reason Length */
#define DERIBIT_ORDERSAPI_REASON_LENGTH_NAME     "Reason Length"
#define DERIBIT_ORDERSAPI_REASON_LENGTH_FILTER   "deribit.ordersapi.reasonlength"
#define DERIBIT_ORDERSAPI_REASON_LENGTH_TYPE     FT_UINT8
#define DERIBIT_ORDERSAPI_REASON_LENGTH_DISPLAY  BASE_DEC
#define DERIBIT_ORDERSAPI_REASON_LENGTH_MASK     0x0
#define DERIBIT_ORDERSAPI_REASON_LENGTH_ENCODING ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_REASON_LENGTH_SIZE     1

static unsigned
parse_deribit_ordersapi_reason_length(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_reason_length, tvb, offset, DERIBIT_ORDERSAPI_REASON_LENGTH_SIZE, DERIBIT_ORDERSAPI_REASON_LENGTH_ENCODING);

    return offset + DERIBIT_ORDERSAPI_REASON_LENGTH_SIZE;
}

/* Reason Mass Cancel Reject Reason */
#define DERIBIT_ORDERSAPI_REASON_MASS_CANCEL_REJECT_REASON_NAME        "Reason Mass Cancel Reject Reason"
#define DERIBIT_ORDERSAPI_REASON_MASS_CANCEL_REJECT_REASON_DESCRIPTION "reason"
#define DERIBIT_ORDERSAPI_REASON_MASS_CANCEL_REJECT_REASON_FILTER      "deribit.ordersapi.reasonmasscancelrejectreason"
#define DERIBIT_ORDERSAPI_REASON_MASS_CANCEL_REJECT_REASON_TYPE        FT_INT8
#define DERIBIT_ORDERSAPI_REASON_MASS_CANCEL_REJECT_REASON_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_REASON_MASS_CANCEL_REJECT_REASON_MASK        0x0
#define DERIBIT_ORDERSAPI_REASON_MASS_CANCEL_REJECT_REASON_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_REASON_MASS_CANCEL_REJECT_REASON_SIZE        1

static const value_string deribit_ordersapi_reason_mass_cancel_reject_reason_vals[] = {
    { 0, "Error" },
    { 1, "Invalid Mmp Group" },
    { 2, "Client Permission Error" },
    { 3, "Not Allowed By Market State" },
    { 0, NULL }
};

static unsigned
parse_deribit_ordersapi_reason_mass_cancel_reject_reason(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_reason_mass_cancel_reject_reason, tvb, offset, DERIBIT_ORDERSAPI_REASON_MASS_CANCEL_REJECT_REASON_SIZE, DERIBIT_ORDERSAPI_REASON_MASS_CANCEL_REJECT_REASON_ENCODING);

    return offset + DERIBIT_ORDERSAPI_REASON_MASS_CANCEL_REJECT_REASON_SIZE;
}

/* Reason Mass Quote Reject Reason */
#define DERIBIT_ORDERSAPI_REASON_MASS_QUOTE_REJECT_REASON_NAME        "Reason Mass Quote Reject Reason"
#define DERIBIT_ORDERSAPI_REASON_MASS_QUOTE_REJECT_REASON_DESCRIPTION "reason"
#define DERIBIT_ORDERSAPI_REASON_MASS_QUOTE_REJECT_REASON_FILTER      "deribit.ordersapi.reasonmassquoterejectreason"
#define DERIBIT_ORDERSAPI_REASON_MASS_QUOTE_REJECT_REASON_TYPE        FT_INT8
#define DERIBIT_ORDERSAPI_REASON_MASS_QUOTE_REJECT_REASON_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_REASON_MASS_QUOTE_REJECT_REASON_MASK        0x0
#define DERIBIT_ORDERSAPI_REASON_MASS_QUOTE_REJECT_REASON_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_REASON_MASS_QUOTE_REJECT_REASON_SIZE        1

static const value_string deribit_ordersapi_reason_mass_quote_reject_reason_vals[] = {
    { 0, "System Error" },
    { 1, "Invalid Mmp Group" },
    { 2, "Mmp Group Disabled" },
    { 3, "Mmp Group Frozen" },
    { 4, "Too Many Quotes" },
    { 5, "Invalid Instrument" },
    { 6, "Rate Limit" },
    { 7, "Portfolio Locked" },
    { 8, "Duplicate Instrument" },
    { 9, "Mmp Min Freeze Time Not Elapsed" },
    { 0, NULL }
};

static unsigned
parse_deribit_ordersapi_reason_mass_quote_reject_reason(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_reason_mass_quote_reject_reason, tvb, offset, DERIBIT_ORDERSAPI_REASON_MASS_QUOTE_REJECT_REASON_SIZE, DERIBIT_ORDERSAPI_REASON_MASS_QUOTE_REJECT_REASON_ENCODING);

    return offset + DERIBIT_ORDERSAPI_REASON_MASS_QUOTE_REJECT_REASON_SIZE;
}

/* Reason Mmp Status Reject Reason */
#define DERIBIT_ORDERSAPI_REASON_MMP_STATUS_REJECT_REASON_NAME        "Reason Mmp Status Reject Reason"
#define DERIBIT_ORDERSAPI_REASON_MMP_STATUS_REJECT_REASON_DESCRIPTION "reason"
#define DERIBIT_ORDERSAPI_REASON_MMP_STATUS_REJECT_REASON_FILTER      "deribit.ordersapi.reasonmmpstatusrejectreason"
#define DERIBIT_ORDERSAPI_REASON_MMP_STATUS_REJECT_REASON_TYPE        FT_INT8
#define DERIBIT_ORDERSAPI_REASON_MMP_STATUS_REJECT_REASON_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_REASON_MMP_STATUS_REJECT_REASON_MASK        0x0
#define DERIBIT_ORDERSAPI_REASON_MMP_STATUS_REJECT_REASON_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_REASON_MMP_STATUS_REJECT_REASON_SIZE        1

static const value_string deribit_ordersapi_reason_mmp_status_reject_reason_vals[] = {
    { 0, "System Error" },
    { 1, "Invalid Mmp Group" },
    { 0, NULL }
};

static unsigned
parse_deribit_ordersapi_reason_mmp_status_reject_reason(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_reason_mmp_status_reject_reason, tvb, offset, DERIBIT_ORDERSAPI_REASON_MMP_STATUS_REJECT_REASON_SIZE, DERIBIT_ORDERSAPI_REASON_MMP_STATUS_REJECT_REASON_ENCODING);

    return offset + DERIBIT_ORDERSAPI_REASON_MMP_STATUS_REJECT_REASON_SIZE;
}

/* Reason Order Reject Reason */
#define DERIBIT_ORDERSAPI_REASON_ORDER_REJECT_REASON_NAME        "Reason Order Reject Reason"
#define DERIBIT_ORDERSAPI_REASON_ORDER_REJECT_REASON_DESCRIPTION "reason"
#define DERIBIT_ORDERSAPI_REASON_ORDER_REJECT_REASON_FILTER      "deribit.ordersapi.reasonorderrejectreason"
#define DERIBIT_ORDERSAPI_REASON_ORDER_REJECT_REASON_TYPE        FT_INT8
#define DERIBIT_ORDERSAPI_REASON_ORDER_REJECT_REASON_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_REASON_ORDER_REJECT_REASON_MASK        0x0
#define DERIBIT_ORDERSAPI_REASON_ORDER_REJECT_REASON_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_REASON_ORDER_REJECT_REASON_SIZE        1

static const value_string deribit_ordersapi_reason_order_reject_reason_vals[] = {
    { 0, "System Error" },
    { 1, "Invalid Instrument" },
    { 2, "Invalid Field" },
    { 3, "Insufficient Margin" },
    { 4, "Duplicate Client Order Id" },
    { 5, "Invalid Quantity" },
    { 6, "Invalid Price" },
    { 7, "Not Allowed By Market State" },
    { 8, "Post Only" },
    { 9, "Too Many Open Orders" },
    { 10, "Permission Error" },
    { 11, "Portfolio Not Found" },
    { 12, "Order Not Found" },
    { 13, "Mmp Not Configured" },
    { 14, "Mmp Max Quote Qty Exceeded" },
    { 15, "Mmp Group Frozen" },
    { 16, "Invalid Margin Mode" },
    { 17, "In Liquidation" },
    { 18, "Risk Check Timed Out" },
    { 19, "Too Many Pending Replaces" },
    { 20, "Iceberg Not Allowed" },
    { 21, "Invalid Allocations" },
    { 22, "Price Too High" },
    { 23, "Price Too Low" },
    { 24, "Price Band Unavailable" },
    { 25, "Rate Limit" },
    { 26, "Portfolio Locked" },
    { 27, "Position Limit Exceeded" },
    { 28, "Order Size Limit Exceeded" },
    { 29, "Member Speed Bump Limit Exceeded" },
    { 30, "Mmp Min Freeze Time Not Elapsed" },
    { 31, "Cancel Only" },
    { 0, NULL }
};

static unsigned
parse_deribit_ordersapi_reason_order_reject_reason(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_reason_order_reject_reason, tvb, offset, DERIBIT_ORDERSAPI_REASON_ORDER_REJECT_REASON_SIZE, DERIBIT_ORDERSAPI_REASON_ORDER_REJECT_REASON_ENCODING);

    return offset + DERIBIT_ORDERSAPI_REASON_ORDER_REJECT_REASON_SIZE;
}

/* Reason Reject Reason */
#define DERIBIT_ORDERSAPI_REASON_REJECT_REASON_NAME        "Reason Reject Reason"
#define DERIBIT_ORDERSAPI_REASON_REJECT_REASON_DESCRIPTION "reason"
#define DERIBIT_ORDERSAPI_REASON_REJECT_REASON_FILTER      "deribit.ordersapi.reasonrejectreason"
#define DERIBIT_ORDERSAPI_REASON_REJECT_REASON_TYPE        FT_INT8
#define DERIBIT_ORDERSAPI_REASON_REJECT_REASON_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_REASON_REJECT_REASON_MASK        0x0
#define DERIBIT_ORDERSAPI_REASON_REJECT_REASON_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_REASON_REJECT_REASON_SIZE        1

static const value_string deribit_ordersapi_reason_reject_reason_vals[] = {
    { 1, "Invalid Schema Id" },
    { 2, "Invalid Template Id" },
    { 3, "Invalid Block Length" },
    { 4, "Invalid Field Value" },
    { 5, "Message Disabled" },
    { 6, "Gateway Not Active" },
    { 0, NULL }
};

static unsigned
parse_deribit_ordersapi_reason_reject_reason(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_reason_reject_reason, tvb, offset, DERIBIT_ORDERSAPI_REASON_REJECT_REASON_SIZE, DERIBIT_ORDERSAPI_REASON_REJECT_REASON_ENCODING);

    return offset + DERIBIT_ORDERSAPI_REASON_REJECT_REASON_SIZE;
}

/* Receive Time */
#define DERIBIT_ORDERSAPI_RECEIVE_TIME_NAME        "Receive Time"
#define DERIBIT_ORDERSAPI_RECEIVE_TIME_DESCRIPTION "receiveTime"
#define DERIBIT_ORDERSAPI_RECEIVE_TIME_FILTER      "deribit.ordersapi.receivetime"
#define DERIBIT_ORDERSAPI_RECEIVE_TIME_TYPE        FT_ABSOLUTE_TIME
#define DERIBIT_ORDERSAPI_RECEIVE_TIME_DISPLAY     ABSOLUTE_TIME_UTC
#define DERIBIT_ORDERSAPI_RECEIVE_TIME_MASK        0x0
#define DERIBIT_ORDERSAPI_RECEIVE_TIME_ENCODING    ENC_TIME_NSECS | ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_RECEIVE_TIME_SIZE        8

static unsigned
parse_deribit_ordersapi_receive_time(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_receive_time, tvb, offset, DERIBIT_ORDERSAPI_RECEIVE_TIME_SIZE, DERIBIT_ORDERSAPI_RECEIVE_TIME_ENCODING);

    return offset + DERIBIT_ORDERSAPI_RECEIVE_TIME_SIZE;
}

/* Ref Sequence Number */
#define DERIBIT_ORDERSAPI_REF_SEQUENCE_NUMBER_NAME        "Ref Sequence Number"
#define DERIBIT_ORDERSAPI_REF_SEQUENCE_NUMBER_DESCRIPTION "refSequenceNumber"
#define DERIBIT_ORDERSAPI_REF_SEQUENCE_NUMBER_FILTER      "deribit.ordersapi.refsequencenumber"
#define DERIBIT_ORDERSAPI_REF_SEQUENCE_NUMBER_TYPE        FT_INT64
#define DERIBIT_ORDERSAPI_REF_SEQUENCE_NUMBER_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_REF_SEQUENCE_NUMBER_MASK        0x0
#define DERIBIT_ORDERSAPI_REF_SEQUENCE_NUMBER_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_REF_SEQUENCE_NUMBER_SIZE        8

static unsigned
parse_deribit_ordersapi_ref_sequence_number(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_ref_sequence_number, tvb, offset, DERIBIT_ORDERSAPI_REF_SEQUENCE_NUMBER_SIZE, DERIBIT_ORDERSAPI_REF_SEQUENCE_NUMBER_ENCODING);

    return offset + DERIBIT_ORDERSAPI_REF_SEQUENCE_NUMBER_SIZE;
}

/* Reserved 10 */
#define DERIBIT_ORDERSAPI_RESERVED_10_NAME        "Reserved 10"
#define DERIBIT_ORDERSAPI_RESERVED_10_DESCRIPTION "10 reserved bits"
#define DERIBIT_ORDERSAPI_RESERVED_10_FILTER      "deribit.ordersapi.reserved10"
#define DERIBIT_ORDERSAPI_RESERVED_10_TYPE        FT_BOOLEAN
#define DERIBIT_ORDERSAPI_RESERVED_10_DISPLAY     8
#define DERIBIT_ORDERSAPI_RESERVED_10_MASK        0xFFC0

/* Reserved 13 */
#define DERIBIT_ORDERSAPI_RESERVED_13_NAME        "Reserved 13"
#define DERIBIT_ORDERSAPI_RESERVED_13_DESCRIPTION "13 reserved bits"
#define DERIBIT_ORDERSAPI_RESERVED_13_FILTER      "deribit.ordersapi.reserved13"
#define DERIBIT_ORDERSAPI_RESERVED_13_TYPE        FT_BOOLEAN
#define DERIBIT_ORDERSAPI_RESERVED_13_DISPLAY     8
#define DERIBIT_ORDERSAPI_RESERVED_13_MASK        0xFFF8

/* Reserved 6 */
#define DERIBIT_ORDERSAPI_RESERVED_6_NAME        "Reserved 6"
#define DERIBIT_ORDERSAPI_RESERVED_6_DESCRIPTION "6 reserved bits"
#define DERIBIT_ORDERSAPI_RESERVED_6_FILTER      "deribit.ordersapi.reserved6"
#define DERIBIT_ORDERSAPI_RESERVED_6_TYPE        FT_BOOLEAN
#define DERIBIT_ORDERSAPI_RESERVED_6_DISPLAY     8
#define DERIBIT_ORDERSAPI_RESERVED_6_MASK        0xFC

/* Reserved 7 */
#define DERIBIT_ORDERSAPI_RESERVED_7_NAME        "Reserved 7"
#define DERIBIT_ORDERSAPI_RESERVED_7_DESCRIPTION "7 reserved bits"
#define DERIBIT_ORDERSAPI_RESERVED_7_FILTER      "deribit.ordersapi.reserved7"
#define DERIBIT_ORDERSAPI_RESERVED_7_TYPE        FT_BOOLEAN
#define DERIBIT_ORDERSAPI_RESERVED_7_DISPLAY     8
#define DERIBIT_ORDERSAPI_RESERVED_7_MASK        0xFE

/* Reset Mmp */
#define DERIBIT_ORDERSAPI_RESET_MMP_NAME        "Reset Mmp"
#define DERIBIT_ORDERSAPI_RESET_MMP_DESCRIPTION "resetMmp"
#define DERIBIT_ORDERSAPI_RESET_MMP_FILTER      "deribit.ordersapi.resetmmp"
#define DERIBIT_ORDERSAPI_RESET_MMP_TYPE        FT_BOOLEAN
#define DERIBIT_ORDERSAPI_RESET_MMP_DISPLAY     8
#define DERIBIT_ORDERSAPI_RESET_MMP_MASK        0x20

/* Reset Seq Num */
#define DERIBIT_ORDERSAPI_RESET_SEQ_NUM_NAME        "Reset Seq Num"
#define DERIBIT_ORDERSAPI_RESET_SEQ_NUM_DESCRIPTION "resetSeqNum"
#define DERIBIT_ORDERSAPI_RESET_SEQ_NUM_FILTER      "deribit.ordersapi.resetseqnum"
#define DERIBIT_ORDERSAPI_RESET_SEQ_NUM_TYPE        FT_INT8
#define DERIBIT_ORDERSAPI_RESET_SEQ_NUM_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_RESET_SEQ_NUM_MASK        0x0
#define DERIBIT_ORDERSAPI_RESET_SEQ_NUM_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_RESET_SEQ_NUM_SIZE        1

static const value_string deribit_ordersapi_reset_seq_num_vals[] = {
    { 0, "False" },
    { 1, "True" },
    { 0, NULL }
};

static unsigned
parse_deribit_ordersapi_reset_seq_num(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_reset_seq_num, tvb, offset, DERIBIT_ORDERSAPI_RESET_SEQ_NUM_SIZE, DERIBIT_ORDERSAPI_RESET_SEQ_NUM_ENCODING);

    return offset + DERIBIT_ORDERSAPI_RESET_SEQ_NUM_SIZE;
}

/* Schema Version */
#define DERIBIT_ORDERSAPI_SCHEMA_VERSION_NAME        "Schema Version"
#define DERIBIT_ORDERSAPI_SCHEMA_VERSION_DESCRIPTION "schemaVersion"
#define DERIBIT_ORDERSAPI_SCHEMA_VERSION_FILTER      "deribit.ordersapi.schemaversion"
#define DERIBIT_ORDERSAPI_SCHEMA_VERSION_TYPE        FT_UINT16
#define DERIBIT_ORDERSAPI_SCHEMA_VERSION_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_SCHEMA_VERSION_MASK        0x0
#define DERIBIT_ORDERSAPI_SCHEMA_VERSION_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_SCHEMA_VERSION_SIZE        2

static unsigned
parse_deribit_ordersapi_schema_version(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_schema_version, tvb, offset, DERIBIT_ORDERSAPI_SCHEMA_VERSION_SIZE, DERIBIT_ORDERSAPI_SCHEMA_VERSION_ENCODING);

    return offset + DERIBIT_ORDERSAPI_SCHEMA_VERSION_SIZE;
}

/* Secret */
#define DERIBIT_ORDERSAPI_SECRET_NAME     "Secret"
#define DERIBIT_ORDERSAPI_SECRET_FILTER   "deribit.ordersapi.secret"
#define DERIBIT_ORDERSAPI_SECRET_TYPE     FT_STRING
#define DERIBIT_ORDERSAPI_SECRET_DISPLAY  BASE_NONE
#define DERIBIT_ORDERSAPI_SECRET_MASK     0x0
#define DERIBIT_ORDERSAPI_SECRET_ENCODING ENC_ASCII
#define DERIBIT_ORDERSAPI_SECRET_SIZE     48

static unsigned
parse_deribit_ordersapi_secret(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_secret, tvb, offset, DERIBIT_ORDERSAPI_SECRET_SIZE, DERIBIT_ORDERSAPI_SECRET_ENCODING);

    return offset + DERIBIT_ORDERSAPI_SECRET_SIZE;
}

/* Self Match Prevention Id */
#define DERIBIT_ORDERSAPI_SELF_MATCH_PREVENTION_ID_NAME        "Self Match Prevention Id"
#define DERIBIT_ORDERSAPI_SELF_MATCH_PREVENTION_ID_DESCRIPTION "selfMatchPreventionId"
#define DERIBIT_ORDERSAPI_SELF_MATCH_PREVENTION_ID_FILTER      "deribit.ordersapi.selfmatchpreventionid"
#define DERIBIT_ORDERSAPI_SELF_MATCH_PREVENTION_ID_TYPE        FT_INT64
#define DERIBIT_ORDERSAPI_SELF_MATCH_PREVENTION_ID_DISPLAY     BASE_CUSTOM
#define DERIBIT_ORDERSAPI_SELF_MATCH_PREVENTION_ID_MASK        0x0
#define DERIBIT_ORDERSAPI_SELF_MATCH_PREVENTION_ID_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_SELF_MATCH_PREVENTION_ID_SIZE        8

static unsigned
parse_deribit_ordersapi_self_match_prevention_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_self_match_prevention_id, tvb, offset, DERIBIT_ORDERSAPI_SELF_MATCH_PREVENTION_ID_SIZE, DERIBIT_ORDERSAPI_SELF_MATCH_PREVENTION_ID_ENCODING);

    return offset + DERIBIT_ORDERSAPI_SELF_MATCH_PREVENTION_ID_SIZE;
}

/* Self Trading Mode */
#define DERIBIT_ORDERSAPI_SELF_TRADING_MODE_NAME        "Self Trading Mode"
#define DERIBIT_ORDERSAPI_SELF_TRADING_MODE_DESCRIPTION "selfTradingMode"
#define DERIBIT_ORDERSAPI_SELF_TRADING_MODE_FILTER      "deribit.ordersapi.selftradingmode"
#define DERIBIT_ORDERSAPI_SELF_TRADING_MODE_TYPE        FT_INT8
#define DERIBIT_ORDERSAPI_SELF_TRADING_MODE_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_SELF_TRADING_MODE_MASK        0x0
#define DERIBIT_ORDERSAPI_SELF_TRADING_MODE_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_SELF_TRADING_MODE_SIZE        1

static const value_string deribit_ordersapi_self_trading_mode_vals[] = {
    { 0, "Cancel Taker" },
    { 1, "Cancel Maker" },
    { 0, NULL }
};

static unsigned
parse_deribit_ordersapi_self_trading_mode(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_self_trading_mode, tvb, offset, DERIBIT_ORDERSAPI_SELF_TRADING_MODE_SIZE, DERIBIT_ORDERSAPI_SELF_TRADING_MODE_ENCODING);

    return offset + DERIBIT_ORDERSAPI_SELF_TRADING_MODE_SIZE;
}

/* Send Time Ns */
#define DERIBIT_ORDERSAPI_SEND_TIME_NS_NAME        "Send Time Ns"
#define DERIBIT_ORDERSAPI_SEND_TIME_NS_DESCRIPTION "UTC timestamp of when the message was sent from the gateway, nanoseconds since Unix epoch (January 1st, 1970, 00:00:00 GMT)"
#define DERIBIT_ORDERSAPI_SEND_TIME_NS_FILTER      "deribit.ordersapi.sendtimens"
#define DERIBIT_ORDERSAPI_SEND_TIME_NS_TYPE        FT_ABSOLUTE_TIME
#define DERIBIT_ORDERSAPI_SEND_TIME_NS_DISPLAY     ABSOLUTE_TIME_UTC
#define DERIBIT_ORDERSAPI_SEND_TIME_NS_MASK        0x0
#define DERIBIT_ORDERSAPI_SEND_TIME_NS_ENCODING    ENC_TIME_NSECS | ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_SEND_TIME_NS_SIZE        8

static unsigned
parse_deribit_ordersapi_send_time_ns(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_send_time_ns, tvb, offset, DERIBIT_ORDERSAPI_SEND_TIME_NS_SIZE, DERIBIT_ORDERSAPI_SEND_TIME_NS_ENCODING);

    return offset + DERIBIT_ORDERSAPI_SEND_TIME_NS_SIZE;
}

/* Sequence Number */
#define DERIBIT_ORDERSAPI_SEQUENCE_NUMBER_NAME        "Sequence Number"
#define DERIBIT_ORDERSAPI_SEQUENCE_NUMBER_DESCRIPTION "Outbound sequence number per session"
#define DERIBIT_ORDERSAPI_SEQUENCE_NUMBER_FILTER      "deribit.ordersapi.sequencenumber"
#define DERIBIT_ORDERSAPI_SEQUENCE_NUMBER_TYPE        FT_INT64
#define DERIBIT_ORDERSAPI_SEQUENCE_NUMBER_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_SEQUENCE_NUMBER_MASK        0x0
#define DERIBIT_ORDERSAPI_SEQUENCE_NUMBER_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_SEQUENCE_NUMBER_SIZE        8

static unsigned
parse_deribit_ordersapi_sequence_number(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_sequence_number, tvb, offset, DERIBIT_ORDERSAPI_SEQUENCE_NUMBER_SIZE, DERIBIT_ORDERSAPI_SEQUENCE_NUMBER_ENCODING);

    return offset + DERIBIT_ORDERSAPI_SEQUENCE_NUMBER_SIZE;
}

/* Session Cancel On Disconnect */
#define DERIBIT_ORDERSAPI_SESSION_CANCEL_ON_DISCONNECT_NAME        "Session Cancel On Disconnect"
#define DERIBIT_ORDERSAPI_SESSION_CANCEL_ON_DISCONNECT_DESCRIPTION "sessionCancelOnDisconnect"
#define DERIBIT_ORDERSAPI_SESSION_CANCEL_ON_DISCONNECT_FILTER      "deribit.ordersapi.sessioncancelondisconnect"
#define DERIBIT_ORDERSAPI_SESSION_CANCEL_ON_DISCONNECT_TYPE        FT_INT8
#define DERIBIT_ORDERSAPI_SESSION_CANCEL_ON_DISCONNECT_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_SESSION_CANCEL_ON_DISCONNECT_MASK        0x0
#define DERIBIT_ORDERSAPI_SESSION_CANCEL_ON_DISCONNECT_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_SESSION_CANCEL_ON_DISCONNECT_SIZE        1

static const value_string deribit_ordersapi_session_cancel_on_disconnect_vals[] = {
    { 0, "False" },
    { 1, "True" },
    { 0, NULL }
};

static unsigned
parse_deribit_ordersapi_session_cancel_on_disconnect(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_session_cancel_on_disconnect, tvb, offset, DERIBIT_ORDERSAPI_SESSION_CANCEL_ON_DISCONNECT_SIZE, DERIBIT_ORDERSAPI_SESSION_CANCEL_ON_DISCONNECT_ENCODING);

    return offset + DERIBIT_ORDERSAPI_SESSION_CANCEL_ON_DISCONNECT_SIZE;
}

/* Side */
#define DERIBIT_ORDERSAPI_SIDE_NAME     "Side"
#define DERIBIT_ORDERSAPI_SIDE_FIX      1059
#define DERIBIT_ORDERSAPI_SIDE_FILTER   "deribit.ordersapi.side"
#define DERIBIT_ORDERSAPI_SIDE_TYPE     FT_INT8
#define DERIBIT_ORDERSAPI_SIDE_DISPLAY  BASE_DEC
#define DERIBIT_ORDERSAPI_SIDE_MASK     0x0
#define DERIBIT_ORDERSAPI_SIDE_ENCODING ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_SIDE_SIZE     1

static const value_string deribit_ordersapi_side_vals[] = {
    { 1, "Buy" },
    { 0, "Both" },
    { -1, "Sell" },
    { 0, NULL }
};

static unsigned
parse_deribit_ordersapi_side(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_side, tvb, offset, DERIBIT_ORDERSAPI_SIDE_SIZE, DERIBIT_ORDERSAPI_SIDE_ENCODING);

    return offset + DERIBIT_ORDERSAPI_SIDE_SIZE;
}

/* Status */
#define DERIBIT_ORDERSAPI_STATUS_NAME     "Status"
#define DERIBIT_ORDERSAPI_STATUS_FIX      1061
#define DERIBIT_ORDERSAPI_STATUS_FILTER   "deribit.ordersapi.status"
#define DERIBIT_ORDERSAPI_STATUS_TYPE     FT_INT8
#define DERIBIT_ORDERSAPI_STATUS_DISPLAY  BASE_DEC
#define DERIBIT_ORDERSAPI_STATUS_MASK     0x0
#define DERIBIT_ORDERSAPI_STATUS_ENCODING ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_STATUS_SIZE     1

static const value_string deribit_ordersapi_status_vals[] = {
    { 1, "Active" },
    { 2, "Filled" },
    { 3, "Canceled" },
    { 4, "Queued" },
    { 0, NULL }
};

static unsigned
parse_deribit_ordersapi_status(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_status, tvb, offset, DERIBIT_ORDERSAPI_STATUS_SIZE, DERIBIT_ORDERSAPI_STATUS_ENCODING);

    return offset + DERIBIT_ORDERSAPI_STATUS_SIZE;
}

/* Template Id values the dispatch switches on */
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGON                              1
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGON_CONF                         2
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGOUT                             4
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGGED_OUT                         5
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_HEARTBEAT                          10
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_TEST_REQUEST                       11
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_RESEND_REQUEST                     20
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_GAP_FILL                           21
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_REJECT                             30
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_NEW_ORDER_REQUEST                  100
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_AMEND_ORDER_REQUEST                110
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_REQUEST               120
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_BY_ID_REQUEST         125
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_REQUEST                 130
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_REQUEST                140
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_CANCEL_REQUEST          145
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_MASS_QUOTE_MMP_STATUS_REQUEST  155
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_ORDERS_MMP_STATUS_REQUEST      156
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_NEW_ORDER_RESPONSE                 200
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_NEW_ORDER_REJECT                   202
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_AMEND_ORDER_RESPONSE               210
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_AMEND_ORDER_REJECT                 212
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_RESPONSE              220
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_REJECT                222
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_RESPONSE                230
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_REJECT                  232
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_RESPONSE               240
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_REJECT                 242
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_MASS_QUOTE_MMP_STATUS_RESPONSE 280
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_MASS_QUOTE_MMP_STATUS_REJECT   281
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_ORDERS_MMP_STATUS_RESPONSE     282
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_ORDERS_MMP_STATUS_REJECT       283
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDER_FILLED                       300
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDERS_CANCELED                    310
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDER_PLACED                       312
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_ORDERS_PLACED           314
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_MMP_TRIGGERED           320
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDERS_MMP_TRIGGERED               322
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_MMP_UNFROZEN            324
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDERS_MMP_UNFROZEN                326

/* Template Id */
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_NAME        "Template Id"
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_DESCRIPTION "Identifier of the message type"
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_FILTER      "deribit.ordersapi.templateid"
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_TYPE        FT_UINT16
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_MASK        0x0
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_TEMPLATE_ID_SIZE        2

static const value_string deribit_ordersapi_template_id_vals[] = {
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGON, "Logon Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGON_CONF, "Logon Conf Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGOUT, "Logout Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGGED_OUT, "Logged Out Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_HEARTBEAT, "Heartbeat Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_TEST_REQUEST, "Test Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_RESEND_REQUEST, "Resend Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_GAP_FILL, "Gap Fill Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_REJECT, "Reject Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_NEW_ORDER_REQUEST, "New Order Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_AMEND_ORDER_REQUEST, "Amend Order Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_REQUEST, "Cancel Order Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_BY_ID_REQUEST, "Cancel Order By Id Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_REQUEST, "Mass Quote Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_REQUEST, "Mass Cancel Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_CANCEL_REQUEST, "Mass Quote Cancel Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_MASS_QUOTE_MMP_STATUS_REQUEST, "Get Mass Quote Mmp Status Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_ORDERS_MMP_STATUS_REQUEST, "Get Orders Mmp Status Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_NEW_ORDER_RESPONSE, "New Order Response Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_NEW_ORDER_REJECT, "New Order Reject Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_AMEND_ORDER_RESPONSE, "Amend Order Response Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_AMEND_ORDER_REJECT, "Amend Order Reject Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_RESPONSE, "Cancel Order Response Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_REJECT, "Cancel Order Reject Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_RESPONSE, "Mass Quote Response Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_REJECT, "Mass Quote Reject Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_RESPONSE, "Mass Cancel Response Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_REJECT, "Mass Cancel Reject Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_MASS_QUOTE_MMP_STATUS_RESPONSE, "Get Mass Quote Mmp Status Response Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_MASS_QUOTE_MMP_STATUS_REJECT, "Get Mass Quote Mmp Status Reject Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_ORDERS_MMP_STATUS_RESPONSE, "Get Orders Mmp Status Response Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_ORDERS_MMP_STATUS_REJECT, "Get Orders Mmp Status Reject Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDER_FILLED, "Order Filled Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDERS_CANCELED, "Orders Canceled Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDER_PLACED, "Order Placed Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_ORDERS_PLACED, "Mass Quote Orders Placed Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_MMP_TRIGGERED, "Mass Quote Mmp Triggered Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDERS_MMP_TRIGGERED, "Orders Mmp Triggered Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_MMP_UNFROZEN, "Mass Quote Mmp Unfrozen Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDERS_MMP_UNFROZEN, "Orders Mmp Unfrozen Message" },
    { 0, NULL }
};

static unsigned
parse_deribit_ordersapi_template_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_template_id, tvb, offset, DERIBIT_ORDERSAPI_TEMPLATE_ID_SIZE, DERIBIT_ORDERSAPI_TEMPLATE_ID_ENCODING);

    return offset + DERIBIT_ORDERSAPI_TEMPLATE_ID_SIZE;
}

/* Time In Force */
#define DERIBIT_ORDERSAPI_TIME_IN_FORCE_NAME        "Time In Force"
#define DERIBIT_ORDERSAPI_TIME_IN_FORCE_DESCRIPTION "timeInForce"
#define DERIBIT_ORDERSAPI_TIME_IN_FORCE_FILTER      "deribit.ordersapi.timeinforce"
#define DERIBIT_ORDERSAPI_TIME_IN_FORCE_TYPE        FT_INT8
#define DERIBIT_ORDERSAPI_TIME_IN_FORCE_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_TIME_IN_FORCE_MASK        0x0
#define DERIBIT_ORDERSAPI_TIME_IN_FORCE_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_TIME_IN_FORCE_SIZE        1

static unsigned
parse_deribit_ordersapi_time_in_force(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_time_in_force, tvb, offset, DERIBIT_ORDERSAPI_TIME_IN_FORCE_SIZE, DERIBIT_ORDERSAPI_TIME_IN_FORCE_ENCODING);

    return offset + DERIBIT_ORDERSAPI_TIME_IN_FORCE_SIZE;
}

/* Timestamp */
#define DERIBIT_ORDERSAPI_TIMESTAMP_NAME     "Timestamp"
#define DERIBIT_ORDERSAPI_TIMESTAMP_FILTER   "deribit.ordersapi.timestamp"
#define DERIBIT_ORDERSAPI_TIMESTAMP_TYPE     FT_ABSOLUTE_TIME
#define DERIBIT_ORDERSAPI_TIMESTAMP_DISPLAY  ABSOLUTE_TIME_UTC
#define DERIBIT_ORDERSAPI_TIMESTAMP_MASK     0x0
#define DERIBIT_ORDERSAPI_TIMESTAMP_ENCODING ENC_TIME_NSECS | ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_TIMESTAMP_SIZE     8

static unsigned
parse_deribit_ordersapi_timestamp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_timestamp, tvb, offset, DERIBIT_ORDERSAPI_TIMESTAMP_SIZE, DERIBIT_ORDERSAPI_TIMESTAMP_ENCODING);

    return offset + DERIBIT_ORDERSAPI_TIMESTAMP_SIZE;
}

/* To Sequence Number */
#define DERIBIT_ORDERSAPI_TO_SEQUENCE_NUMBER_NAME        "To Sequence Number"
#define DERIBIT_ORDERSAPI_TO_SEQUENCE_NUMBER_DESCRIPTION "toSequenceNumber"
#define DERIBIT_ORDERSAPI_TO_SEQUENCE_NUMBER_FILTER      "deribit.ordersapi.tosequencenumber"
#define DERIBIT_ORDERSAPI_TO_SEQUENCE_NUMBER_TYPE        FT_INT64
#define DERIBIT_ORDERSAPI_TO_SEQUENCE_NUMBER_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_TO_SEQUENCE_NUMBER_MASK        0x0
#define DERIBIT_ORDERSAPI_TO_SEQUENCE_NUMBER_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_TO_SEQUENCE_NUMBER_SIZE        8

static unsigned
parse_deribit_ordersapi_to_sequence_number(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_to_sequence_number, tvb, offset, DERIBIT_ORDERSAPI_TO_SEQUENCE_NUMBER_SIZE, DERIBIT_ORDERSAPI_TO_SEQUENCE_NUMBER_ENCODING);

    return offset + DERIBIT_ORDERSAPI_TO_SEQUENCE_NUMBER_SIZE;
}

/* Total Order Count */
#define DERIBIT_ORDERSAPI_TOTAL_ORDER_COUNT_NAME        "Total Order Count"
#define DERIBIT_ORDERSAPI_TOTAL_ORDER_COUNT_DESCRIPTION "totalOrderCount"
#define DERIBIT_ORDERSAPI_TOTAL_ORDER_COUNT_FILTER      "deribit.ordersapi.totalordercount"
#define DERIBIT_ORDERSAPI_TOTAL_ORDER_COUNT_TYPE        FT_INT32
#define DERIBIT_ORDERSAPI_TOTAL_ORDER_COUNT_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_TOTAL_ORDER_COUNT_MASK        0x0
#define DERIBIT_ORDERSAPI_TOTAL_ORDER_COUNT_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_TOTAL_ORDER_COUNT_SIZE        4

static unsigned
parse_deribit_ordersapi_total_order_count(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_total_order_count, tvb, offset, DERIBIT_ORDERSAPI_TOTAL_ORDER_COUNT_SIZE, DERIBIT_ORDERSAPI_TOTAL_ORDER_COUNT_ENCODING);

    return offset + DERIBIT_ORDERSAPI_TOTAL_ORDER_COUNT_SIZE;
}

/* Trigger */
#define DERIBIT_ORDERSAPI_TRIGGER_NAME     "Trigger"
#define DERIBIT_ORDERSAPI_TRIGGER_FILTER   "deribit.ordersapi.trigger"
#define DERIBIT_ORDERSAPI_TRIGGER_TYPE     FT_INT8
#define DERIBIT_ORDERSAPI_TRIGGER_DISPLAY  BASE_DEC
#define DERIBIT_ORDERSAPI_TRIGGER_MASK     0x0
#define DERIBIT_ORDERSAPI_TRIGGER_ENCODING ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_TRIGGER_SIZE     1

static const value_string deribit_ordersapi_trigger_vals[] = {
    { 0, "Quantity" },
    { 1, "Delta" },
    { 2, "Vega" },
    { 0, NULL }
};

static unsigned
parse_deribit_ordersapi_trigger(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_trigger, tvb, offset, DERIBIT_ORDERSAPI_TRIGGER_SIZE, DERIBIT_ORDERSAPI_TRIGGER_ENCODING);

    return offset + DERIBIT_ORDERSAPI_TRIGGER_SIZE;
}

/* Unused Order Flags 0 */
#define DERIBIT_ORDERSAPI_UNUSED_ORDER_FLAGS_0_NAME        "Unused Order Flags 0"
#define DERIBIT_ORDERSAPI_UNUSED_ORDER_FLAGS_0_DESCRIPTION "Unused OrderFlags 0"
#define DERIBIT_ORDERSAPI_UNUSED_ORDER_FLAGS_0_FILTER      "deribit.ordersapi.unusedorderflags0"
#define DERIBIT_ORDERSAPI_UNUSED_ORDER_FLAGS_0_TYPE        FT_BOOLEAN
#define DERIBIT_ORDERSAPI_UNUSED_ORDER_FLAGS_0_DISPLAY     8
#define DERIBIT_ORDERSAPI_UNUSED_ORDER_FLAGS_0_MASK        0x01

/* Unused Replace Order Flags 0 */
#define DERIBIT_ORDERSAPI_UNUSED_REPLACE_ORDER_FLAGS_0_NAME        "Unused Replace Order Flags 0"
#define DERIBIT_ORDERSAPI_UNUSED_REPLACE_ORDER_FLAGS_0_DESCRIPTION "Unused ReplaceOrderFlags 0"
#define DERIBIT_ORDERSAPI_UNUSED_REPLACE_ORDER_FLAGS_0_FILTER      "deribit.ordersapi.unusedreplaceorderflags0"
#define DERIBIT_ORDERSAPI_UNUSED_REPLACE_ORDER_FLAGS_0_TYPE        FT_BOOLEAN
#define DERIBIT_ORDERSAPI_UNUSED_REPLACE_ORDER_FLAGS_0_DISPLAY     8
#define DERIBIT_ORDERSAPI_UNUSED_REPLACE_ORDER_FLAGS_0_MASK        0x01

/* Vega Level */
#define DERIBIT_ORDERSAPI_VEGA_LEVEL_NAME        "Vega Level"
#define DERIBIT_ORDERSAPI_VEGA_LEVEL_DESCRIPTION "vegaLevel"
#define DERIBIT_ORDERSAPI_VEGA_LEVEL_FILTER      "deribit.ordersapi.vegalevel"
#define DERIBIT_ORDERSAPI_VEGA_LEVEL_TYPE        FT_UINT64
#define DERIBIT_ORDERSAPI_VEGA_LEVEL_DISPLAY     BASE_DEC
#define DERIBIT_ORDERSAPI_VEGA_LEVEL_MASK        0x0
#define DERIBIT_ORDERSAPI_VEGA_LEVEL_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_VEGA_LEVEL_SIZE        8

static unsigned
parse_deribit_ordersapi_vega_level(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_deribit_ordersapi_vega_level, tvb, offset, DERIBIT_ORDERSAPI_VEGA_LEVEL_SIZE, DERIBIT_ORDERSAPI_VEGA_LEVEL_ENCODING);

    return offset + DERIBIT_ORDERSAPI_VEGA_LEVEL_SIZE;
}

/*
 * Deribit OrdersApi Structs
 */

/* Session Flags */
#define DERIBIT_ORDERSAPI_SESSION_FLAGS_NAME        "Session Flags"
#define DERIBIT_ORDERSAPI_SESSION_FLAGS_DESCRIPTION "Uint8 bit set carrying the isResend indicator"
#define DERIBIT_ORDERSAPI_SESSION_FLAGS_FILTER      "deribit.ordersapi.sessionflags"
#define DERIBIT_ORDERSAPI_SESSION_FLAGS_TYPE        FT_UINT8
#define DERIBIT_ORDERSAPI_SESSION_FLAGS_DISPLAY     BASE_HEX
#define DERIBIT_ORDERSAPI_SESSION_FLAGS_MASK        0x0
#define DERIBIT_ORDERSAPI_SESSION_FLAGS_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_SESSION_FLAGS_SIZE        1

static int * const deribit_ordersapi_session_flags_fields[] = {
    &hf_deribit_ordersapi_is_resend,
    NULL
};

static unsigned
parse_deribit_ordersapi_session_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_bitmask(tree, tvb, offset, hf_deribit_ordersapi_session_flags,
        ett_deribit_ordersapi_session_flags, deribit_ordersapi_session_flags_fields, DERIBIT_ORDERSAPI_SESSION_FLAGS_ENCODING);

    return offset + DERIBIT_ORDERSAPI_SESSION_FLAGS_SIZE;
}

/* Flags Order Flags */
#define DERIBIT_ORDERSAPI_FLAGS_ORDER_FLAGS_NAME        "Flags Order Flags"
#define DERIBIT_ORDERSAPI_FLAGS_ORDER_FLAGS_DESCRIPTION "OrderFlags bit set"
#define DERIBIT_ORDERSAPI_FLAGS_ORDER_FLAGS_FILTER      "deribit.ordersapi.flagsorderflags"
#define DERIBIT_ORDERSAPI_FLAGS_ORDER_FLAGS_TYPE        FT_UINT16
#define DERIBIT_ORDERSAPI_FLAGS_ORDER_FLAGS_DISPLAY     BASE_HEX
#define DERIBIT_ORDERSAPI_FLAGS_ORDER_FLAGS_MASK        0x0
#define DERIBIT_ORDERSAPI_FLAGS_ORDER_FLAGS_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_FLAGS_ORDER_FLAGS_SIZE        2

static int * const deribit_ordersapi_flags_order_flags_fields[] = {
    &hf_deribit_ordersapi_reserved_10,
    &hf_deribit_ordersapi_reset_mmp,
    &hf_deribit_ordersapi_mmp,
    &hf_deribit_ordersapi_market_limit,
    &hf_deribit_ordersapi_post_only_reject,
    &hf_deribit_ordersapi_post_only,
    &hf_deribit_ordersapi_cancel_on_disconnect,
    NULL
};

static unsigned
parse_deribit_ordersapi_flags_order_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_bitmask(tree, tvb, offset, hf_deribit_ordersapi_flags_order_flags,
        ett_deribit_ordersapi_flags_order_flags, deribit_ordersapi_flags_order_flags_fields, DERIBIT_ORDERSAPI_FLAGS_ORDER_FLAGS_ENCODING);

    return offset + DERIBIT_ORDERSAPI_FLAGS_ORDER_FLAGS_SIZE;
}

/* Flags Replace Order Flags */
#define DERIBIT_ORDERSAPI_FLAGS_REPLACE_ORDER_FLAGS_NAME        "Flags Replace Order Flags"
#define DERIBIT_ORDERSAPI_FLAGS_REPLACE_ORDER_FLAGS_DESCRIPTION "ReplaceOrderFlags bit set"
#define DERIBIT_ORDERSAPI_FLAGS_REPLACE_ORDER_FLAGS_FILTER      "deribit.ordersapi.flagsreplaceorderflags"
#define DERIBIT_ORDERSAPI_FLAGS_REPLACE_ORDER_FLAGS_TYPE        FT_UINT16
#define DERIBIT_ORDERSAPI_FLAGS_REPLACE_ORDER_FLAGS_DISPLAY     BASE_HEX
#define DERIBIT_ORDERSAPI_FLAGS_REPLACE_ORDER_FLAGS_MASK        0x0
#define DERIBIT_ORDERSAPI_FLAGS_REPLACE_ORDER_FLAGS_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_FLAGS_REPLACE_ORDER_FLAGS_SIZE        2

static int * const deribit_ordersapi_flags_replace_order_flags_fields[] = {
    &hf_deribit_ordersapi_reserved_13,
    &hf_deribit_ordersapi_post_only_reject,
    &hf_deribit_ordersapi_post_only,
    &hf_deribit_ordersapi_unused_replace_order_flags_0,
    NULL
};

static unsigned
parse_deribit_ordersapi_flags_replace_order_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_bitmask(tree, tvb, offset, hf_deribit_ordersapi_flags_replace_order_flags,
        ett_deribit_ordersapi_flags_replace_order_flags, deribit_ordersapi_flags_replace_order_flags_fields, DERIBIT_ORDERSAPI_FLAGS_REPLACE_ORDER_FLAGS_ENCODING);

    return offset + DERIBIT_ORDERSAPI_FLAGS_REPLACE_ORDER_FLAGS_SIZE;
}

/* Flags Mass Quote Flags */
#define DERIBIT_ORDERSAPI_FLAGS_MASS_QUOTE_FLAGS_NAME        "Flags Mass Quote Flags"
#define DERIBIT_ORDERSAPI_FLAGS_MASS_QUOTE_FLAGS_DESCRIPTION "MassQuoteFlags bit set"
#define DERIBIT_ORDERSAPI_FLAGS_MASS_QUOTE_FLAGS_FILTER      "deribit.ordersapi.flagsmassquoteflags"
#define DERIBIT_ORDERSAPI_FLAGS_MASS_QUOTE_FLAGS_TYPE        FT_UINT8
#define DERIBIT_ORDERSAPI_FLAGS_MASS_QUOTE_FLAGS_DISPLAY     BASE_HEX
#define DERIBIT_ORDERSAPI_FLAGS_MASS_QUOTE_FLAGS_MASK        0x0
#define DERIBIT_ORDERSAPI_FLAGS_MASS_QUOTE_FLAGS_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_FLAGS_MASS_QUOTE_FLAGS_SIZE        1

static int * const deribit_ordersapi_flags_mass_quote_flags_fields[] = {
    &hf_deribit_ordersapi_reserved_7,
    &hf_deribit_ordersapi_reset_mmp,
    NULL
};

static unsigned
parse_deribit_ordersapi_flags_mass_quote_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_bitmask(tree, tvb, offset, hf_deribit_ordersapi_flags_mass_quote_flags,
        ett_deribit_ordersapi_flags_mass_quote_flags, deribit_ordersapi_flags_mass_quote_flags_fields, DERIBIT_ORDERSAPI_FLAGS_MASS_QUOTE_FLAGS_ENCODING);

    return offset + DERIBIT_ORDERSAPI_FLAGS_MASS_QUOTE_FLAGS_SIZE;
}

/* Bid Flags */
#define DERIBIT_ORDERSAPI_BID_FLAGS_NAME        "Bid Flags"
#define DERIBIT_ORDERSAPI_BID_FLAGS_DESCRIPTION "OrderFlags bit set"
#define DERIBIT_ORDERSAPI_BID_FLAGS_FILTER      "deribit.ordersapi.bidflags"
#define DERIBIT_ORDERSAPI_BID_FLAGS_TYPE        FT_UINT16
#define DERIBIT_ORDERSAPI_BID_FLAGS_DISPLAY     BASE_HEX
#define DERIBIT_ORDERSAPI_BID_FLAGS_MASK        0x0
#define DERIBIT_ORDERSAPI_BID_FLAGS_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_BID_FLAGS_SIZE        2

static int * const deribit_ordersapi_bid_flags_fields[] = {
    &hf_deribit_ordersapi_reserved_10,
    &hf_deribit_ordersapi_reset_mmp,
    &hf_deribit_ordersapi_mmp,
    &hf_deribit_ordersapi_market_limit,
    &hf_deribit_ordersapi_post_only_reject,
    &hf_deribit_ordersapi_post_only,
    &hf_deribit_ordersapi_cancel_on_disconnect,
    NULL
};

static unsigned
parse_deribit_ordersapi_bid_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_bitmask(tree, tvb, offset, hf_deribit_ordersapi_bid_flags,
        ett_deribit_ordersapi_bid_flags, deribit_ordersapi_bid_flags_fields, DERIBIT_ORDERSAPI_BID_FLAGS_ENCODING);

    return offset + DERIBIT_ORDERSAPI_BID_FLAGS_SIZE;
}

/* Ask Flags */
#define DERIBIT_ORDERSAPI_ASK_FLAGS_NAME        "Ask Flags"
#define DERIBIT_ORDERSAPI_ASK_FLAGS_DESCRIPTION "OrderFlags bit set"
#define DERIBIT_ORDERSAPI_ASK_FLAGS_FILTER      "deribit.ordersapi.askflags"
#define DERIBIT_ORDERSAPI_ASK_FLAGS_TYPE        FT_UINT16
#define DERIBIT_ORDERSAPI_ASK_FLAGS_DISPLAY     BASE_HEX
#define DERIBIT_ORDERSAPI_ASK_FLAGS_MASK        0x0
#define DERIBIT_ORDERSAPI_ASK_FLAGS_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_ASK_FLAGS_SIZE        2

static int * const deribit_ordersapi_ask_flags_fields[] = {
    &hf_deribit_ordersapi_reserved_10,
    &hf_deribit_ordersapi_reset_mmp,
    &hf_deribit_ordersapi_mmp,
    &hf_deribit_ordersapi_market_limit,
    &hf_deribit_ordersapi_post_only_reject,
    &hf_deribit_ordersapi_post_only,
    &hf_deribit_ordersapi_cancel_on_disconnect,
    NULL
};

static unsigned
parse_deribit_ordersapi_ask_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_bitmask(tree, tvb, offset, hf_deribit_ordersapi_ask_flags,
        ett_deribit_ordersapi_ask_flags, deribit_ordersapi_ask_flags_fields, DERIBIT_ORDERSAPI_ASK_FLAGS_ENCODING);

    return offset + DERIBIT_ORDERSAPI_ASK_FLAGS_SIZE;
}

/* Flags Fill Flags */
#define DERIBIT_ORDERSAPI_FLAGS_FILL_FLAGS_NAME        "Flags Fill Flags"
#define DERIBIT_ORDERSAPI_FLAGS_FILL_FLAGS_DESCRIPTION "FillFlags bit set"
#define DERIBIT_ORDERSAPI_FLAGS_FILL_FLAGS_FILTER      "deribit.ordersapi.flagsfillflags"
#define DERIBIT_ORDERSAPI_FLAGS_FILL_FLAGS_TYPE        FT_UINT8
#define DERIBIT_ORDERSAPI_FLAGS_FILL_FLAGS_DISPLAY     BASE_HEX
#define DERIBIT_ORDERSAPI_FLAGS_FILL_FLAGS_MASK        0x0
#define DERIBIT_ORDERSAPI_FLAGS_FILL_FLAGS_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_FLAGS_FILL_FLAGS_SIZE        1

static int * const deribit_ordersapi_flags_fill_flags_fields[] = {
    &hf_deribit_ordersapi_reserved_6,
    &hf_deribit_ordersapi_is_fully_filled,
    &hf_deribit_ordersapi_is_quote,
    NULL
};

static unsigned
parse_deribit_ordersapi_flags_fill_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_bitmask(tree, tvb, offset, hf_deribit_ordersapi_flags_fill_flags,
        ett_deribit_ordersapi_flags_fill_flags, deribit_ordersapi_flags_fill_flags_fields, DERIBIT_ORDERSAPI_FLAGS_FILL_FLAGS_ENCODING);

    return offset + DERIBIT_ORDERSAPI_FLAGS_FILL_FLAGS_SIZE;
}

/* Flags Multi Part Event Flags */
#define DERIBIT_ORDERSAPI_FLAGS_MULTI_PART_EVENT_FLAGS_NAME        "Flags Multi Part Event Flags"
#define DERIBIT_ORDERSAPI_FLAGS_MULTI_PART_EVENT_FLAGS_DESCRIPTION "MultiPartEventFlags bit set"
#define DERIBIT_ORDERSAPI_FLAGS_MULTI_PART_EVENT_FLAGS_FILTER      "deribit.ordersapi.flagsmultiparteventflags"
#define DERIBIT_ORDERSAPI_FLAGS_MULTI_PART_EVENT_FLAGS_TYPE        FT_UINT8
#define DERIBIT_ORDERSAPI_FLAGS_MULTI_PART_EVENT_FLAGS_DISPLAY     BASE_HEX
#define DERIBIT_ORDERSAPI_FLAGS_MULTI_PART_EVENT_FLAGS_MASK        0x0
#define DERIBIT_ORDERSAPI_FLAGS_MULTI_PART_EVENT_FLAGS_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_FLAGS_MULTI_PART_EVENT_FLAGS_SIZE        1

static int * const deribit_ordersapi_flags_multi_part_event_flags_fields[] = {
    &hf_deribit_ordersapi_reserved_7,
    &hf_deribit_ordersapi_is_last_message,
    NULL
};

static unsigned
parse_deribit_ordersapi_flags_multi_part_event_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_bitmask(tree, tvb, offset, hf_deribit_ordersapi_flags_multi_part_event_flags,
        ett_deribit_ordersapi_flags_multi_part_event_flags, deribit_ordersapi_flags_multi_part_event_flags_fields, DERIBIT_ORDERSAPI_FLAGS_MULTI_PART_EVENT_FLAGS_ENCODING);

    return offset + DERIBIT_ORDERSAPI_FLAGS_MULTI_PART_EVENT_FLAGS_SIZE;
}

/* Flags Cancel Flags */
#define DERIBIT_ORDERSAPI_FLAGS_CANCEL_FLAGS_NAME        "Flags Cancel Flags"
#define DERIBIT_ORDERSAPI_FLAGS_CANCEL_FLAGS_DESCRIPTION "CancelFlags bit set"
#define DERIBIT_ORDERSAPI_FLAGS_CANCEL_FLAGS_FILTER      "deribit.ordersapi.flagscancelflags"
#define DERIBIT_ORDERSAPI_FLAGS_CANCEL_FLAGS_TYPE        FT_UINT8
#define DERIBIT_ORDERSAPI_FLAGS_CANCEL_FLAGS_DISPLAY     BASE_HEX
#define DERIBIT_ORDERSAPI_FLAGS_CANCEL_FLAGS_MASK        0x0
#define DERIBIT_ORDERSAPI_FLAGS_CANCEL_FLAGS_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_FLAGS_CANCEL_FLAGS_SIZE        1

static int * const deribit_ordersapi_flags_cancel_flags_fields[] = {
    &hf_deribit_ordersapi_reserved_7,
    &hf_deribit_ordersapi_is_quote,
    NULL
};

static unsigned
parse_deribit_ordersapi_flags_cancel_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_bitmask(tree, tvb, offset, hf_deribit_ordersapi_flags_cancel_flags,
        ett_deribit_ordersapi_flags_cancel_flags, deribit_ordersapi_flags_cancel_flags_fields, DERIBIT_ORDERSAPI_FLAGS_CANCEL_FLAGS_ENCODING);

    return offset + DERIBIT_ORDERSAPI_FLAGS_CANCEL_FLAGS_SIZE;
}

/* Flags Order Flags */
#define DERIBIT_ORDERSAPI_FLAGS_ORDER_FLAGS_V10_NAME        "Flags Order Flags"
#define DERIBIT_ORDERSAPI_FLAGS_ORDER_FLAGS_V10_DESCRIPTION "OrderFlags bit set"
#define DERIBIT_ORDERSAPI_FLAGS_ORDER_FLAGS_V10_FILTER      "deribit.ordersapi.flagsorderflags"
#define DERIBIT_ORDERSAPI_FLAGS_ORDER_FLAGS_V10_TYPE        FT_UINT16
#define DERIBIT_ORDERSAPI_FLAGS_ORDER_FLAGS_V10_DISPLAY     BASE_HEX
#define DERIBIT_ORDERSAPI_FLAGS_ORDER_FLAGS_V10_MASK        0x0
#define DERIBIT_ORDERSAPI_FLAGS_ORDER_FLAGS_V10_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_FLAGS_ORDER_FLAGS_V10_SIZE        2

static int * const deribit_ordersapi_flags_order_flags_v10_fields[] = {
    &hf_deribit_ordersapi_reserved_10,
    &hf_deribit_ordersapi_reset_mmp,
    &hf_deribit_ordersapi_mmp,
    &hf_deribit_ordersapi_market_limit,
    &hf_deribit_ordersapi_post_only_reject,
    &hf_deribit_ordersapi_post_only,
    &hf_deribit_ordersapi_unused_order_flags_0,
    NULL
};

static unsigned
parse_deribit_ordersapi_flags_order_flags_v10(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_bitmask(tree, tvb, offset, hf_deribit_ordersapi_flags_order_flags_v10,
        ett_deribit_ordersapi_flags_order_flags_v10, deribit_ordersapi_flags_order_flags_v10_fields, DERIBIT_ORDERSAPI_FLAGS_ORDER_FLAGS_V10_ENCODING);

    return offset + DERIBIT_ORDERSAPI_FLAGS_ORDER_FLAGS_V10_SIZE;
}

/* Bid Flags */
#define DERIBIT_ORDERSAPI_BID_FLAGS_V10_NAME        "Bid Flags"
#define DERIBIT_ORDERSAPI_BID_FLAGS_V10_DESCRIPTION "OrderFlags bit set"
#define DERIBIT_ORDERSAPI_BID_FLAGS_V10_FILTER      "deribit.ordersapi.bidflags"
#define DERIBIT_ORDERSAPI_BID_FLAGS_V10_TYPE        FT_UINT16
#define DERIBIT_ORDERSAPI_BID_FLAGS_V10_DISPLAY     BASE_HEX
#define DERIBIT_ORDERSAPI_BID_FLAGS_V10_MASK        0x0
#define DERIBIT_ORDERSAPI_BID_FLAGS_V10_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_BID_FLAGS_V10_SIZE        2

static int * const deribit_ordersapi_bid_flags_v10_fields[] = {
    &hf_deribit_ordersapi_reserved_10,
    &hf_deribit_ordersapi_reset_mmp,
    &hf_deribit_ordersapi_mmp,
    &hf_deribit_ordersapi_market_limit,
    &hf_deribit_ordersapi_post_only_reject,
    &hf_deribit_ordersapi_post_only,
    &hf_deribit_ordersapi_unused_order_flags_0,
    NULL
};

static unsigned
parse_deribit_ordersapi_bid_flags_v10(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_bitmask(tree, tvb, offset, hf_deribit_ordersapi_bid_flags_v10,
        ett_deribit_ordersapi_bid_flags_v10, deribit_ordersapi_bid_flags_v10_fields, DERIBIT_ORDERSAPI_BID_FLAGS_V10_ENCODING);

    return offset + DERIBIT_ORDERSAPI_BID_FLAGS_V10_SIZE;
}

/* Ask Flags */
#define DERIBIT_ORDERSAPI_ASK_FLAGS_V10_NAME        "Ask Flags"
#define DERIBIT_ORDERSAPI_ASK_FLAGS_V10_DESCRIPTION "OrderFlags bit set"
#define DERIBIT_ORDERSAPI_ASK_FLAGS_V10_FILTER      "deribit.ordersapi.askflags"
#define DERIBIT_ORDERSAPI_ASK_FLAGS_V10_TYPE        FT_UINT16
#define DERIBIT_ORDERSAPI_ASK_FLAGS_V10_DISPLAY     BASE_HEX
#define DERIBIT_ORDERSAPI_ASK_FLAGS_V10_MASK        0x0
#define DERIBIT_ORDERSAPI_ASK_FLAGS_V10_ENCODING    ENC_LITTLE_ENDIAN
#define DERIBIT_ORDERSAPI_ASK_FLAGS_V10_SIZE        2

static int * const deribit_ordersapi_ask_flags_v10_fields[] = {
    &hf_deribit_ordersapi_reserved_10,
    &hf_deribit_ordersapi_reset_mmp,
    &hf_deribit_ordersapi_mmp,
    &hf_deribit_ordersapi_market_limit,
    &hf_deribit_ordersapi_post_only_reject,
    &hf_deribit_ordersapi_post_only,
    &hf_deribit_ordersapi_unused_order_flags_0,
    NULL
};

static unsigned
parse_deribit_ordersapi_ask_flags_v10(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_bitmask(tree, tvb, offset, hf_deribit_ordersapi_ask_flags_v10,
        ett_deribit_ordersapi_ask_flags_v10, deribit_ordersapi_ask_flags_v10_fields, DERIBIT_ORDERSAPI_ASK_FLAGS_V10_ENCODING);

    return offset + DERIBIT_ORDERSAPI_ASK_FLAGS_V10_SIZE;
}

/* Message and group dissect methods */
static unsigned dissect_deribit_ordersapi_message_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_logon(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_logon_conf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_logout(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_reason(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_logged_out(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_heartbeat(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_test_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_resend_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_gap_fill(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_reject(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_details(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_new_order_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_quantity(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_show_qty(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_amend_order_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_cancel_order_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_cancel_order_by_id_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_mass_quote_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_mass_quote_request_message_quotes_groups(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_group_size_encoding(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_mass_quote_request_message_quotes_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t index);
static unsigned dissect_deribit_ordersapi_bid_qty(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_ask_qty(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_mass_cancel_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_mass_quote_cancel_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_get_mass_quote_mmp_status_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_get_orders_mmp_status_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_new_order_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_total_filled(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_visible_qty(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_new_order_response_message_fills_groups(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_new_order_response_message_fills_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t index);
static unsigned dissect_deribit_ordersapi_fill_qty(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_new_order_response_message_legs_groups(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_new_order_response_message_legs_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t index);
static unsigned dissect_deribit_ordersapi_new_order_reject(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_amend_order_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_amend_order_response_message_fills_groups(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_amend_order_response_message_fills_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t index);
static unsigned dissect_deribit_ordersapi_amend_order_response_message_legs_groups(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_amend_order_response_message_legs_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t index);
static unsigned dissect_deribit_ordersapi_amend_order_reject(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_cancel_order_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_cancel_order_reject(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_mass_quote_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_mass_quote_response_message_quotes_groups(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_mass_quote_response_message_quotes_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t index);
static unsigned dissect_deribit_ordersapi_bid_filled_qty(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_ask_filled_qty(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_mass_quote_response_message_bid_fills_groups(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_mass_quote_response_message_bid_fills_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t index);
static unsigned dissect_deribit_ordersapi_mass_quote_response_message_ask_fills_groups(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_mass_quote_response_message_ask_fills_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t index);
static unsigned dissect_deribit_ordersapi_mass_quote_response_message_legs_groups(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_mass_quote_response_message_legs_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t index);
static unsigned dissect_deribit_ordersapi_mass_quote_reject(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_mass_cancel_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_mass_cancel_reject(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_get_mass_quote_mmp_status_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_get_mass_quote_mmp_status_reject(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_get_orders_mmp_status_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_get_orders_mmp_status_reject(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_order_filled(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_order_filled_message_fills_groups(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_order_filled_message_fills_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t index);
static unsigned dissect_deribit_ordersapi_order_filled_message_legs_groups(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_order_filled_message_legs_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t index);
static unsigned dissect_deribit_ordersapi_orders_canceled(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_orders_canceled_message_orders_groups(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_orders_canceled_message_orders_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t index);
static unsigned dissect_deribit_ordersapi_order_placed(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_order_placed_message_fills_groups(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_order_placed_message_fills_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t index);
static unsigned dissect_deribit_ordersapi_order_placed_message_legs_groups(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_order_placed_message_legs_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t index);
static unsigned dissect_deribit_ordersapi_mass_quote_orders_placed(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_mass_quote_orders_placed_message_orders_groups(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_mass_quote_orders_placed_message_orders_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t index);
static unsigned dissect_deribit_ordersapi_mass_quote_orders_placed_message_fills_groups(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_mass_quote_orders_placed_message_fills_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t index);
static unsigned dissect_deribit_ordersapi_mass_quote_orders_placed_message_legs_groups(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_mass_quote_orders_placed_message_legs_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t index);
static unsigned dissect_deribit_ordersapi_mass_quote_mmp_triggered(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_orders_mmp_triggered(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_mass_quote_mmp_unfrozen(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_orders_mmp_unfrozen(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_logon_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_new_order_response_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_cancel_order_response_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_logon_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_logon_conf_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_new_order_response_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_cancel_order_response_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_logon_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_logon_conf_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_new_order_request_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_mass_quote_request_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_mass_quote_request_message_quotes_groups_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_mass_quote_request_message_quotes_group_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t index);
static unsigned dissect_deribit_ordersapi_new_order_response_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_cancel_order_response_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_order_placed_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_logon_v01(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_logon_conf_v01(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_new_order_request_v01(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_mass_quote_request_v01(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_new_order_response_v01(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_cancel_order_response_v01(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_order_placed_v01(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_deribit_ordersapi_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id);
static unsigned dissect_deribit_ordersapi_payload_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id);
static unsigned dissect_deribit_ordersapi_payload_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id);
static unsigned dissect_deribit_ordersapi_payload_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id);
static unsigned dissect_deribit_ordersapi_payload_v01(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id);

/* Message Header */
static unsigned
dissect_deribit_ordersapi_message_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_headers) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_message_header, &item, "Message Header");
    }

    unsigned start = offset;

    offset = parse_deribit_ordersapi_protocol_id(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_session_flags(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_message_length(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_template_id(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_schema_version(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_sequence_number(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_last_processed_seq_no(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_send_time_ns(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Logon Message */
static unsigned
dissect_deribit_ordersapi_logon(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_client_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_secret(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_reset_seq_num(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_schema_version(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_session_cancel_on_disconnect(tvb, pinfo, tree, offset);

    return offset;
}

/* Logon Conf Message */
static unsigned
dissect_deribit_ordersapi_logon_conf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_heartbeat_interval_seconds(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_schema_version(tvb, pinfo, tree, offset);

    return offset;
}

/* Logout Message */
static unsigned
dissect_deribit_ordersapi_logout(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = dissect_deribit_ordersapi_reason(tvb, pinfo, tree, offset);

    return offset;
}

/* Reason */
static unsigned
dissect_deribit_ordersapi_reason(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_reason, &item, "Reason");
    }

    unsigned start = offset;

    offset = parse_deribit_ordersapi_reason_length(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_reason_data(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Logged Out Message */
static unsigned
dissect_deribit_ordersapi_logged_out(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = dissect_deribit_ordersapi_reason(tvb, pinfo, tree, offset);

    return offset;
}

/* Heartbeat Message */
static unsigned
dissect_deribit_ordersapi_heartbeat(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_correlation_id(tvb, pinfo, tree, offset);

    return offset;
}

/* Test Request Message */
static unsigned
dissect_deribit_ordersapi_test_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_correlation_id(tvb, pinfo, tree, offset);

    return offset;
}

/* Resend Request Message */
static unsigned
dissect_deribit_ordersapi_resend_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_from_sequence_number(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_to_sequence_number(tvb, pinfo, tree, offset);

    return offset;
}

/* Gap Fill Message */
static unsigned
dissect_deribit_ordersapi_gap_fill(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_new_sequence_number(tvb, pinfo, tree, offset);

    return offset;
}

/* Reject Message */
static unsigned
dissect_deribit_ordersapi_reject(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_ref_sequence_number(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_reason_reject_reason(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_details(tvb, pinfo, tree, offset);

    return offset;
}

/* Details */
static unsigned
dissect_deribit_ordersapi_details(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_details, &item, "Details");
    }

    unsigned start = offset;

    offset = parse_deribit_ordersapi_details_length(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_details_data(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* New Order Request Message */
static unsigned
dissect_deribit_ordersapi_new_order_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_client_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_price(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_quantity(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_show_qty(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_self_match_prevention_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_side(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_time_in_force(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_flags_order_flags(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_self_trading_mode(tvb, pinfo, tree, offset);

    return offset;
}

/* Quantity */
static unsigned
dissect_deribit_ordersapi_quantity(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_quantity, &item, "Quantity");
    }

    unsigned start = offset;

    offset = parse_deribit_ordersapi_mantissa(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_exponent(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Show Qty */
static unsigned
dissect_deribit_ordersapi_show_qty(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_show_qty, &item, "Show Qty");
    }

    unsigned start = offset;

    offset = parse_deribit_ordersapi_mantissa(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_exponent(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Amend Order Request Message */
static unsigned
dissect_deribit_ordersapi_amend_order_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_client_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_price(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_quantity(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_show_qty(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_flags_replace_order_flags(tvb, pinfo, tree, offset);

    return offset;
}

/* Cancel Order Request Message */
static unsigned
dissect_deribit_ordersapi_cancel_order_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_client_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_instrument_id(tvb, pinfo, tree, offset);

    return offset;
}

/* Cancel Order By Id Request Message */
static unsigned
dissect_deribit_ordersapi_cancel_order_by_id_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_instrument_id(tvb, pinfo, tree, offset);

    return offset;
}

/* Mass Quote Request Message */
static unsigned
dissect_deribit_ordersapi_mass_quote_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_quote_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_mmp_group_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_self_match_prevention_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_flags_mass_quote_flags(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_mass_quote_request_message_quotes_groups(tvb, pinfo, tree, offset);

    return offset;
}

/* Mass Quote Request Message quotes Groups */
static unsigned
dissect_deribit_ordersapi_mass_quote_request_message_quotes_groups(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_mass_quote_request_message_quotes_groups, &item, "Mass Quote Request Message quotes Groups");
    }

    unsigned start = offset;

    offset = dissect_deribit_ordersapi_group_size_encoding(tvb, pinfo, group, offset);

    /* Mass Quote Request Message quotes Group: Num In Group entries */
    uint32_t num_in_group = tvb_get_letohs(tvb, start + 2);

    for (uint32_t index = 0; index < num_in_group; index++) {
        offset = dissect_deribit_ordersapi_mass_quote_request_message_quotes_group(tvb, pinfo, group, offset, index + 1);
    }

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Group Size Encoding */
static unsigned
dissect_deribit_ordersapi_group_size_encoding(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_group_size_encoding, &item, "Group Size Encoding");
    }

    unsigned start = offset;

    offset = parse_deribit_ordersapi_block_length(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_num_in_group(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Mass Quote Request Message quotes Group */
static unsigned
dissect_deribit_ordersapi_mass_quote_request_message_quotes_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t index)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = deribit_ordersapi_pref_show_indexes
            ? proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_deribit_ordersapi_mass_quote_request_message_quotes_group, &item, "Mass Quote Request Message quotes Group %u", index)
            : proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_mass_quote_request_message_quotes_group, &item, "Mass Quote Request Message quotes Group");
    }

    unsigned start = offset;

    offset = parse_deribit_ordersapi_instrument_id(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_bid_price_optional(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_ask_price_optional(tvb, pinfo, group, offset);
    offset = dissect_deribit_ordersapi_bid_qty(tvb, pinfo, group, offset);
    offset = dissect_deribit_ordersapi_ask_qty(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_bid_flags(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_ask_flags(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Bid Qty */
static unsigned
dissect_deribit_ordersapi_bid_qty(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_bid_qty, &item, "Bid Qty");
    }

    unsigned start = offset;

    offset = parse_deribit_ordersapi_mantissa(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_exponent(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Ask Qty */
static unsigned
dissect_deribit_ordersapi_ask_qty(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_ask_qty, &item, "Ask Qty");
    }

    unsigned start = offset;

    offset = parse_deribit_ordersapi_mantissa(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_exponent(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Mass Cancel Request Message */
static unsigned
dissect_deribit_ordersapi_mass_cancel_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_currency_pair_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_instrument_id_optional(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_product_type(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_side(tvb, pinfo, tree, offset);

    return offset;
}

/* Mass Quote Cancel Request Message */
static unsigned
dissect_deribit_ordersapi_mass_quote_cancel_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_mmp_group_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_side(tvb, pinfo, tree, offset);

    return offset;
}

/* Get Mass Quote Mmp Status Request Message */
static unsigned
dissect_deribit_ordersapi_get_mass_quote_mmp_status_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_mmp_group_id(tvb, pinfo, tree, offset);

    return offset;
}

/* Get Orders Mmp Status Request Message */
static unsigned
dissect_deribit_ordersapi_get_orders_mmp_status_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_currency_pair_id(tvb, pinfo, tree, offset);

    return offset;
}

/* New Order Response Message */
static unsigned
dissect_deribit_ordersapi_new_order_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_exec_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_client_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_price(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_quantity(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_total_filled(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_visible_qty(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_receive_time(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_side(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_status(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_cancel_reason(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_flags_order_flags(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_new_order_response_message_fills_groups(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_new_order_response_message_legs_groups(tvb, pinfo, tree, offset);

    return offset;
}

/* Total Filled */
static unsigned
dissect_deribit_ordersapi_total_filled(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_total_filled, &item, "Total Filled");
    }

    unsigned start = offset;

    offset = parse_deribit_ordersapi_mantissa(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_exponent(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Visible Qty */
static unsigned
dissect_deribit_ordersapi_visible_qty(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_visible_qty, &item, "Visible Qty");
    }

    unsigned start = offset;

    offset = parse_deribit_ordersapi_mantissa(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_exponent(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* New Order Response Message fills Groups */
static unsigned
dissect_deribit_ordersapi_new_order_response_message_fills_groups(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_new_order_response_message_fills_groups, &item, "New Order Response Message fills Groups");
    }

    unsigned start = offset;

    offset = dissect_deribit_ordersapi_group_size_encoding(tvb, pinfo, group, offset);

    /* New Order Response Message fills Group: Num In Group entries */
    uint32_t num_in_group = tvb_get_letohs(tvb, start + 2);

    for (uint32_t index = 0; index < num_in_group; index++) {
        offset = dissect_deribit_ordersapi_new_order_response_message_fills_group(tvb, pinfo, group, offset, index + 1);
    }

    proto_item_set_len(item, offset - start);

    return offset;
}

/* New Order Response Message fills Group */
static unsigned
dissect_deribit_ordersapi_new_order_response_message_fills_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t index)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = deribit_ordersapi_pref_show_indexes
            ? proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_deribit_ordersapi_new_order_response_message_fills_group, &item, "New Order Response Message fills Group %u", index)
            : proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_new_order_response_message_fills_group, &item, "New Order Response Message fills Group");
    }

    unsigned start = offset;

    offset = parse_deribit_ordersapi_match_id(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_fill_price(tvb, pinfo, group, offset);
    offset = dissect_deribit_ordersapi_fill_qty(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Fill Qty */
static unsigned
dissect_deribit_ordersapi_fill_qty(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_fill_qty, &item, "Fill Qty");
    }

    unsigned start = offset;

    offset = parse_deribit_ordersapi_mantissa(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_exponent(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* New Order Response Message legs Groups */
static unsigned
dissect_deribit_ordersapi_new_order_response_message_legs_groups(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_new_order_response_message_legs_groups, &item, "New Order Response Message legs Groups");
    }

    unsigned start = offset;

    offset = dissect_deribit_ordersapi_group_size_encoding(tvb, pinfo, group, offset);

    /* New Order Response Message legs Group: Num In Group entries */
    uint32_t num_in_group = tvb_get_letohs(tvb, start + 2);

    for (uint32_t index = 0; index < num_in_group; index++) {
        offset = dissect_deribit_ordersapi_new_order_response_message_legs_group(tvb, pinfo, group, offset, index + 1);
    }

    proto_item_set_len(item, offset - start);

    return offset;
}

/* New Order Response Message legs Group */
static unsigned
dissect_deribit_ordersapi_new_order_response_message_legs_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t index)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = deribit_ordersapi_pref_show_indexes
            ? proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_deribit_ordersapi_new_order_response_message_legs_group, &item, "New Order Response Message legs Group %u", index)
            : proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_new_order_response_message_legs_group, &item, "New Order Response Message legs Group");
    }

    unsigned start = offset;

    offset = parse_deribit_ordersapi_match_id(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_fill_id(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_fill_price(tvb, pinfo, group, offset);
    offset = dissect_deribit_ordersapi_fill_qty(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_leg_side(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* New Order Reject Message */
static unsigned
dissect_deribit_ordersapi_new_order_reject(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_exec_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_client_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_reason_order_reject_reason(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_details(tvb, pinfo, tree, offset);

    return offset;
}

/* Amend Order Response Message */
static unsigned
dissect_deribit_ordersapi_amend_order_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_exec_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_client_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_price(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_quantity(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_total_filled(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_visible_qty(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_receive_time(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_status(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_cancel_reason(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_amend_order_response_message_fills_groups(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_amend_order_response_message_legs_groups(tvb, pinfo, tree, offset);

    return offset;
}

/* Amend Order Response Message fills Groups */
static unsigned
dissect_deribit_ordersapi_amend_order_response_message_fills_groups(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_amend_order_response_message_fills_groups, &item, "Amend Order Response Message fills Groups");
    }

    unsigned start = offset;

    offset = dissect_deribit_ordersapi_group_size_encoding(tvb, pinfo, group, offset);

    /* Amend Order Response Message fills Group: Num In Group entries */
    uint32_t num_in_group = tvb_get_letohs(tvb, start + 2);

    for (uint32_t index = 0; index < num_in_group; index++) {
        offset = dissect_deribit_ordersapi_amend_order_response_message_fills_group(tvb, pinfo, group, offset, index + 1);
    }

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Amend Order Response Message fills Group */
static unsigned
dissect_deribit_ordersapi_amend_order_response_message_fills_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t index)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = deribit_ordersapi_pref_show_indexes
            ? proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_deribit_ordersapi_amend_order_response_message_fills_group, &item, "Amend Order Response Message fills Group %u", index)
            : proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_amend_order_response_message_fills_group, &item, "Amend Order Response Message fills Group");
    }

    unsigned start = offset;

    offset = parse_deribit_ordersapi_match_id(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_fill_price(tvb, pinfo, group, offset);
    offset = dissect_deribit_ordersapi_fill_qty(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Amend Order Response Message legs Groups */
static unsigned
dissect_deribit_ordersapi_amend_order_response_message_legs_groups(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_amend_order_response_message_legs_groups, &item, "Amend Order Response Message legs Groups");
    }

    unsigned start = offset;

    offset = dissect_deribit_ordersapi_group_size_encoding(tvb, pinfo, group, offset);

    /* Amend Order Response Message legs Group: Num In Group entries */
    uint32_t num_in_group = tvb_get_letohs(tvb, start + 2);

    for (uint32_t index = 0; index < num_in_group; index++) {
        offset = dissect_deribit_ordersapi_amend_order_response_message_legs_group(tvb, pinfo, group, offset, index + 1);
    }

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Amend Order Response Message legs Group */
static unsigned
dissect_deribit_ordersapi_amend_order_response_message_legs_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t index)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = deribit_ordersapi_pref_show_indexes
            ? proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_deribit_ordersapi_amend_order_response_message_legs_group, &item, "Amend Order Response Message legs Group %u", index)
            : proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_amend_order_response_message_legs_group, &item, "Amend Order Response Message legs Group");
    }

    unsigned start = offset;

    offset = parse_deribit_ordersapi_match_id(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_fill_id(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_fill_price(tvb, pinfo, group, offset);
    offset = dissect_deribit_ordersapi_fill_qty(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_leg_side(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Amend Order Reject Message */
static unsigned
dissect_deribit_ordersapi_amend_order_reject(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_exec_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_client_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_reason_order_reject_reason(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_details(tvb, pinfo, tree, offset);

    return offset;
}

/* Cancel Order Response Message */
static unsigned
dissect_deribit_ordersapi_cancel_order_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_exec_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_client_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_receive_time(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_quantity(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_total_filled(tvb, pinfo, tree, offset);

    return offset;
}

/* Cancel Order Reject Message */
static unsigned
dissect_deribit_ordersapi_cancel_order_reject(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_exec_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_client_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_order_id_optional(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_reason_cancel_order_reject_reason(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_details(tvb, pinfo, tree, offset);

    return offset;
}

/* Mass Quote Response Message */
static unsigned
dissect_deribit_ordersapi_mass_quote_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_exec_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_quote_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_mmp_group_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_receive_time(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_mass_quote_response_message_quotes_groups(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_mass_quote_response_message_bid_fills_groups(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_mass_quote_response_message_ask_fills_groups(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_mass_quote_response_message_legs_groups(tvb, pinfo, tree, offset);

    return offset;
}

/* Mass Quote Response Message quotes Groups */
static unsigned
dissect_deribit_ordersapi_mass_quote_response_message_quotes_groups(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_mass_quote_response_message_quotes_groups, &item, "Mass Quote Response Message quotes Groups");
    }

    unsigned start = offset;

    offset = dissect_deribit_ordersapi_group_size_encoding(tvb, pinfo, group, offset);

    /* Mass Quote Response Message quotes Group: Num In Group entries */
    uint32_t num_in_group = tvb_get_letohs(tvb, start + 2);

    for (uint32_t index = 0; index < num_in_group; index++) {
        offset = dissect_deribit_ordersapi_mass_quote_response_message_quotes_group(tvb, pinfo, group, offset, index + 1);
    }

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Mass Quote Response Message quotes Group */
static unsigned
dissect_deribit_ordersapi_mass_quote_response_message_quotes_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t index)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = deribit_ordersapi_pref_show_indexes
            ? proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_deribit_ordersapi_mass_quote_response_message_quotes_group, &item, "Mass Quote Response Message quotes Group %u", index)
            : proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_mass_quote_response_message_quotes_group, &item, "Mass Quote Response Message quotes Group");
    }

    unsigned start = offset;

    offset = parse_deribit_ordersapi_instrument_id(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_bid_order_id(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_ask_order_id(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_bid_price(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_ask_price(tvb, pinfo, group, offset);
    offset = dissect_deribit_ordersapi_bid_qty(tvb, pinfo, group, offset);
    offset = dissect_deribit_ordersapi_ask_qty(tvb, pinfo, group, offset);
    offset = dissect_deribit_ordersapi_bid_filled_qty(tvb, pinfo, group, offset);
    offset = dissect_deribit_ordersapi_ask_filled_qty(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_bid_status(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_ask_status(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_bid_reject_reason(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_ask_reject_reason(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Bid Filled Qty */
static unsigned
dissect_deribit_ordersapi_bid_filled_qty(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_bid_filled_qty, &item, "Bid Filled Qty");
    }

    unsigned start = offset;

    offset = parse_deribit_ordersapi_mantissa(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_exponent(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Ask Filled Qty */
static unsigned
dissect_deribit_ordersapi_ask_filled_qty(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_ask_filled_qty, &item, "Ask Filled Qty");
    }

    unsigned start = offset;

    offset = parse_deribit_ordersapi_mantissa(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_exponent(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Mass Quote Response Message bid Fills Groups */
static unsigned
dissect_deribit_ordersapi_mass_quote_response_message_bid_fills_groups(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_mass_quote_response_message_bid_fills_groups, &item, "Mass Quote Response Message bid Fills Groups");
    }

    unsigned start = offset;

    offset = dissect_deribit_ordersapi_group_size_encoding(tvb, pinfo, group, offset);

    /* Mass Quote Response Message bid Fills Group: Num In Group entries */
    uint32_t num_in_group = tvb_get_letohs(tvb, start + 2);

    for (uint32_t index = 0; index < num_in_group; index++) {
        offset = dissect_deribit_ordersapi_mass_quote_response_message_bid_fills_group(tvb, pinfo, group, offset, index + 1);
    }

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Mass Quote Response Message bid Fills Group */
static unsigned
dissect_deribit_ordersapi_mass_quote_response_message_bid_fills_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t index)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = deribit_ordersapi_pref_show_indexes
            ? proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_deribit_ordersapi_mass_quote_response_message_bid_fills_group, &item, "Mass Quote Response Message bid Fills Group %u", index)
            : proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_mass_quote_response_message_bid_fills_group, &item, "Mass Quote Response Message bid Fills Group");
    }

    unsigned start = offset;

    offset = parse_deribit_ordersapi_match_id(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_instrument_id(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_fill_price(tvb, pinfo, group, offset);
    offset = dissect_deribit_ordersapi_fill_qty(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Mass Quote Response Message ask Fills Groups */
static unsigned
dissect_deribit_ordersapi_mass_quote_response_message_ask_fills_groups(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_mass_quote_response_message_ask_fills_groups, &item, "Mass Quote Response Message ask Fills Groups");
    }

    unsigned start = offset;

    offset = dissect_deribit_ordersapi_group_size_encoding(tvb, pinfo, group, offset);

    /* Mass Quote Response Message ask Fills Group: Num In Group entries */
    uint32_t num_in_group = tvb_get_letohs(tvb, start + 2);

    for (uint32_t index = 0; index < num_in_group; index++) {
        offset = dissect_deribit_ordersapi_mass_quote_response_message_ask_fills_group(tvb, pinfo, group, offset, index + 1);
    }

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Mass Quote Response Message ask Fills Group */
static unsigned
dissect_deribit_ordersapi_mass_quote_response_message_ask_fills_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t index)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = deribit_ordersapi_pref_show_indexes
            ? proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_deribit_ordersapi_mass_quote_response_message_ask_fills_group, &item, "Mass Quote Response Message ask Fills Group %u", index)
            : proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_mass_quote_response_message_ask_fills_group, &item, "Mass Quote Response Message ask Fills Group");
    }

    unsigned start = offset;

    offset = parse_deribit_ordersapi_match_id(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_instrument_id(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_fill_price(tvb, pinfo, group, offset);
    offset = dissect_deribit_ordersapi_fill_qty(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Mass Quote Response Message legs Groups */
static unsigned
dissect_deribit_ordersapi_mass_quote_response_message_legs_groups(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_mass_quote_response_message_legs_groups, &item, "Mass Quote Response Message legs Groups");
    }

    unsigned start = offset;

    offset = dissect_deribit_ordersapi_group_size_encoding(tvb, pinfo, group, offset);

    /* Mass Quote Response Message legs Group: Num In Group entries */
    uint32_t num_in_group = tvb_get_letohs(tvb, start + 2);

    for (uint32_t index = 0; index < num_in_group; index++) {
        offset = dissect_deribit_ordersapi_mass_quote_response_message_legs_group(tvb, pinfo, group, offset, index + 1);
    }

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Mass Quote Response Message legs Group */
static unsigned
dissect_deribit_ordersapi_mass_quote_response_message_legs_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t index)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = deribit_ordersapi_pref_show_indexes
            ? proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_deribit_ordersapi_mass_quote_response_message_legs_group, &item, "Mass Quote Response Message legs Group %u", index)
            : proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_mass_quote_response_message_legs_group, &item, "Mass Quote Response Message legs Group");
    }

    unsigned start = offset;

    offset = parse_deribit_ordersapi_match_id(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_fill_id(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_fill_price(tvb, pinfo, group, offset);
    offset = dissect_deribit_ordersapi_fill_qty(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_leg_side(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Mass Quote Reject Message */
static unsigned
dissect_deribit_ordersapi_mass_quote_reject(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_exec_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_quote_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_mmp_group_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_reason_mass_quote_reject_reason(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_details(tvb, pinfo, tree, offset);

    return offset;
}

/* Mass Cancel Response Message */
static unsigned
dissect_deribit_ordersapi_mass_cancel_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_exec_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_receive_time(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_total_order_count(tvb, pinfo, tree, offset);

    return offset;
}

/* Mass Cancel Reject Message */
static unsigned
dissect_deribit_ordersapi_mass_cancel_reject(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_exec_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_reason_mass_cancel_reject_reason(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_details(tvb, pinfo, tree, offset);

    return offset;
}

/* Get Mass Quote Mmp Status Response Message */
static unsigned
dissect_deribit_ordersapi_get_mass_quote_mmp_status_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_mmp_group_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_frozen_until_time(tvb, pinfo, tree, offset);

    return offset;
}

/* Get Mass Quote Mmp Status Reject Message */
static unsigned
dissect_deribit_ordersapi_get_mass_quote_mmp_status_reject(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_reason_mmp_status_reject_reason(tvb, pinfo, tree, offset);

    return offset;
}

/* Get Orders Mmp Status Response Message */
static unsigned
dissect_deribit_ordersapi_get_orders_mmp_status_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_currency_pair_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_frozen_until_time(tvb, pinfo, tree, offset);

    return offset;
}

/* Get Orders Mmp Status Reject Message */
static unsigned
dissect_deribit_ordersapi_get_orders_mmp_status_reject(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_reason_mmp_status_reject_reason(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Filled Message */
static unsigned
dissect_deribit_ordersapi_order_filled(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_exec_id(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_order_filled_message_fills_groups(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_order_filled_message_legs_groups(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Filled Message fills Groups */
static unsigned
dissect_deribit_ordersapi_order_filled_message_fills_groups(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_order_filled_message_fills_groups, &item, "Order Filled Message fills Groups");
    }

    unsigned start = offset;

    offset = dissect_deribit_ordersapi_group_size_encoding(tvb, pinfo, group, offset);

    /* Order Filled Message fills Group: Num In Group entries */
    uint32_t num_in_group = tvb_get_letohs(tvb, start + 2);

    for (uint32_t index = 0; index < num_in_group; index++) {
        offset = dissect_deribit_ordersapi_order_filled_message_fills_group(tvb, pinfo, group, offset, index + 1);
    }

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Order Filled Message fills Group */
static unsigned
dissect_deribit_ordersapi_order_filled_message_fills_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t index)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = deribit_ordersapi_pref_show_indexes
            ? proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_deribit_ordersapi_order_filled_message_fills_group, &item, "Order Filled Message fills Group %u", index)
            : proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_order_filled_message_fills_group, &item, "Order Filled Message fills Group");
    }

    unsigned start = offset;

    offset = parse_deribit_ordersapi_client_order_id(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_order_id(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_instrument_id(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_match_id(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_price(tvb, pinfo, group, offset);
    offset = dissect_deribit_ordersapi_fill_qty(tvb, pinfo, group, offset);
    offset = dissect_deribit_ordersapi_total_filled(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_side(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_flags_fill_flags(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Order Filled Message legs Groups */
static unsigned
dissect_deribit_ordersapi_order_filled_message_legs_groups(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_order_filled_message_legs_groups, &item, "Order Filled Message legs Groups");
    }

    unsigned start = offset;

    offset = dissect_deribit_ordersapi_group_size_encoding(tvb, pinfo, group, offset);

    /* Order Filled Message legs Group: Num In Group entries */
    uint32_t num_in_group = tvb_get_letohs(tvb, start + 2);

    for (uint32_t index = 0; index < num_in_group; index++) {
        offset = dissect_deribit_ordersapi_order_filled_message_legs_group(tvb, pinfo, group, offset, index + 1);
    }

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Order Filled Message legs Group */
static unsigned
dissect_deribit_ordersapi_order_filled_message_legs_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t index)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = deribit_ordersapi_pref_show_indexes
            ? proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_deribit_ordersapi_order_filled_message_legs_group, &item, "Order Filled Message legs Group %u", index)
            : proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_order_filled_message_legs_group, &item, "Order Filled Message legs Group");
    }

    unsigned start = offset;

    offset = parse_deribit_ordersapi_match_id(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_fill_id(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_price(tvb, pinfo, group, offset);
    offset = dissect_deribit_ordersapi_fill_qty(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_leg_side(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Orders Canceled Message */
static unsigned
dissect_deribit_ordersapi_orders_canceled(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_exec_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_flags_multi_part_event_flags(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_orders_canceled_message_orders_groups(tvb, pinfo, tree, offset);

    return offset;
}

/* Orders Canceled Message orders Groups */
static unsigned
dissect_deribit_ordersapi_orders_canceled_message_orders_groups(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_orders_canceled_message_orders_groups, &item, "Orders Canceled Message orders Groups");
    }

    unsigned start = offset;

    offset = dissect_deribit_ordersapi_group_size_encoding(tvb, pinfo, group, offset);

    /* Orders Canceled Message orders Group: Num In Group entries */
    uint32_t num_in_group = tvb_get_letohs(tvb, start + 2);

    for (uint32_t index = 0; index < num_in_group; index++) {
        offset = dissect_deribit_ordersapi_orders_canceled_message_orders_group(tvb, pinfo, group, offset, index + 1);
    }

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Orders Canceled Message orders Group */
static unsigned
dissect_deribit_ordersapi_orders_canceled_message_orders_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t index)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = deribit_ordersapi_pref_show_indexes
            ? proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_deribit_ordersapi_orders_canceled_message_orders_group, &item, "Orders Canceled Message orders Group %u", index)
            : proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_orders_canceled_message_orders_group, &item, "Orders Canceled Message orders Group");
    }

    unsigned start = offset;

    offset = parse_deribit_ordersapi_client_order_id(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_order_id(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_instrument_id(tvb, pinfo, group, offset);
    offset = dissect_deribit_ordersapi_total_filled(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_cancel_reason(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_flags_cancel_flags(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Order Placed Message */
static unsigned
dissect_deribit_ordersapi_order_placed(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_exec_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_client_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_price(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_quantity(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_total_filled(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_visible_qty(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_status(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_cancel_reason(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_padding_3(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_order_placed_message_fills_groups(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_order_placed_message_legs_groups(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Placed Message fills Groups */
static unsigned
dissect_deribit_ordersapi_order_placed_message_fills_groups(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_order_placed_message_fills_groups, &item, "Order Placed Message fills Groups");
    }

    unsigned start = offset;

    offset = dissect_deribit_ordersapi_group_size_encoding(tvb, pinfo, group, offset);

    /* Order Placed Message fills Group: Num In Group entries */
    uint32_t num_in_group = tvb_get_letohs(tvb, start + 2);

    for (uint32_t index = 0; index < num_in_group; index++) {
        offset = dissect_deribit_ordersapi_order_placed_message_fills_group(tvb, pinfo, group, offset, index + 1);
    }

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Order Placed Message fills Group */
static unsigned
dissect_deribit_ordersapi_order_placed_message_fills_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t index)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = deribit_ordersapi_pref_show_indexes
            ? proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_deribit_ordersapi_order_placed_message_fills_group, &item, "Order Placed Message fills Group %u", index)
            : proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_order_placed_message_fills_group, &item, "Order Placed Message fills Group");
    }

    unsigned start = offset;

    offset = parse_deribit_ordersapi_match_id(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_fill_price(tvb, pinfo, group, offset);
    offset = dissect_deribit_ordersapi_fill_qty(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Order Placed Message legs Groups */
static unsigned
dissect_deribit_ordersapi_order_placed_message_legs_groups(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_order_placed_message_legs_groups, &item, "Order Placed Message legs Groups");
    }

    unsigned start = offset;

    offset = dissect_deribit_ordersapi_group_size_encoding(tvb, pinfo, group, offset);

    /* Order Placed Message legs Group: Num In Group entries */
    uint32_t num_in_group = tvb_get_letohs(tvb, start + 2);

    for (uint32_t index = 0; index < num_in_group; index++) {
        offset = dissect_deribit_ordersapi_order_placed_message_legs_group(tvb, pinfo, group, offset, index + 1);
    }

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Order Placed Message legs Group */
static unsigned
dissect_deribit_ordersapi_order_placed_message_legs_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t index)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = deribit_ordersapi_pref_show_indexes
            ? proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_deribit_ordersapi_order_placed_message_legs_group, &item, "Order Placed Message legs Group %u", index)
            : proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_order_placed_message_legs_group, &item, "Order Placed Message legs Group");
    }

    unsigned start = offset;

    offset = parse_deribit_ordersapi_match_id(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_fill_id(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_fill_price(tvb, pinfo, group, offset);
    offset = dissect_deribit_ordersapi_fill_qty(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_leg_side(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Mass Quote Orders Placed Message */
static unsigned
dissect_deribit_ordersapi_mass_quote_orders_placed(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_exec_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_mmp_group_id(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_mass_quote_orders_placed_message_orders_groups(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_mass_quote_orders_placed_message_fills_groups(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_mass_quote_orders_placed_message_legs_groups(tvb, pinfo, tree, offset);

    return offset;
}

/* Mass Quote Orders Placed Message orders Groups */
static unsigned
dissect_deribit_ordersapi_mass_quote_orders_placed_message_orders_groups(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_mass_quote_orders_placed_message_orders_groups, &item, "Mass Quote Orders Placed Message orders Groups");
    }

    unsigned start = offset;

    offset = dissect_deribit_ordersapi_group_size_encoding(tvb, pinfo, group, offset);

    /* Mass Quote Orders Placed Message orders Group: Num In Group entries */
    uint32_t num_in_group = tvb_get_letohs(tvb, start + 2);

    for (uint32_t index = 0; index < num_in_group; index++) {
        offset = dissect_deribit_ordersapi_mass_quote_orders_placed_message_orders_group(tvb, pinfo, group, offset, index + 1);
    }

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Mass Quote Orders Placed Message orders Group */
static unsigned
dissect_deribit_ordersapi_mass_quote_orders_placed_message_orders_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t index)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = deribit_ordersapi_pref_show_indexes
            ? proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_deribit_ordersapi_mass_quote_orders_placed_message_orders_group, &item, "Mass Quote Orders Placed Message orders Group %u", index)
            : proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_mass_quote_orders_placed_message_orders_group, &item, "Mass Quote Orders Placed Message orders Group");
    }

    unsigned start = offset;

    offset = parse_deribit_ordersapi_client_order_id(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_order_id(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_instrument_id(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_price(tvb, pinfo, group, offset);
    offset = dissect_deribit_ordersapi_quantity(tvb, pinfo, group, offset);
    offset = dissect_deribit_ordersapi_total_filled(tvb, pinfo, group, offset);
    offset = dissect_deribit_ordersapi_visible_qty(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_side(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_status(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_cancel_reason(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Mass Quote Orders Placed Message fills Groups */
static unsigned
dissect_deribit_ordersapi_mass_quote_orders_placed_message_fills_groups(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_mass_quote_orders_placed_message_fills_groups, &item, "Mass Quote Orders Placed Message fills Groups");
    }

    unsigned start = offset;

    offset = dissect_deribit_ordersapi_group_size_encoding(tvb, pinfo, group, offset);

    /* Mass Quote Orders Placed Message fills Group: Num In Group entries */
    uint32_t num_in_group = tvb_get_letohs(tvb, start + 2);

    for (uint32_t index = 0; index < num_in_group; index++) {
        offset = dissect_deribit_ordersapi_mass_quote_orders_placed_message_fills_group(tvb, pinfo, group, offset, index + 1);
    }

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Mass Quote Orders Placed Message fills Group */
static unsigned
dissect_deribit_ordersapi_mass_quote_orders_placed_message_fills_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t index)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = deribit_ordersapi_pref_show_indexes
            ? proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_deribit_ordersapi_mass_quote_orders_placed_message_fills_group, &item, "Mass Quote Orders Placed Message fills Group %u", index)
            : proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_mass_quote_orders_placed_message_fills_group, &item, "Mass Quote Orders Placed Message fills Group");
    }

    unsigned start = offset;

    offset = parse_deribit_ordersapi_match_id(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_order_id_fill_id(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_fill_price(tvb, pinfo, group, offset);
    offset = dissect_deribit_ordersapi_fill_qty(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Mass Quote Orders Placed Message legs Groups */
static unsigned
dissect_deribit_ordersapi_mass_quote_orders_placed_message_legs_groups(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_mass_quote_orders_placed_message_legs_groups, &item, "Mass Quote Orders Placed Message legs Groups");
    }

    unsigned start = offset;

    offset = dissect_deribit_ordersapi_group_size_encoding(tvb, pinfo, group, offset);

    /* Mass Quote Orders Placed Message legs Group: Num In Group entries */
    uint32_t num_in_group = tvb_get_letohs(tvb, start + 2);

    for (uint32_t index = 0; index < num_in_group; index++) {
        offset = dissect_deribit_ordersapi_mass_quote_orders_placed_message_legs_group(tvb, pinfo, group, offset, index + 1);
    }

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Mass Quote Orders Placed Message legs Group */
static unsigned
dissect_deribit_ordersapi_mass_quote_orders_placed_message_legs_group(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t index)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = deribit_ordersapi_pref_show_indexes
            ? proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_deribit_ordersapi_mass_quote_orders_placed_message_legs_group, &item, "Mass Quote Orders Placed Message legs Group %u", index)
            : proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_mass_quote_orders_placed_message_legs_group, &item, "Mass Quote Orders Placed Message legs Group");
    }

    unsigned start = offset;

    offset = parse_deribit_ordersapi_match_id(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_fill_id(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_fill_price(tvb, pinfo, group, offset);
    offset = dissect_deribit_ordersapi_fill_qty(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_leg_side(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Mass Quote Mmp Triggered Message */
static unsigned
dissect_deribit_ordersapi_mass_quote_mmp_triggered(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_exec_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_mmp_group_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_frozen_until(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_quantity_level(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_vega_level(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_delta_level(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_trigger(tvb, pinfo, tree, offset);

    return offset;
}

/* Orders Mmp Triggered Message */
static unsigned
dissect_deribit_ordersapi_orders_mmp_triggered(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_exec_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_currency_pair_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_frozen_until(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_quantity_level(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_vega_level(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_delta_level(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_trigger(tvb, pinfo, tree, offset);

    return offset;
}

/* Mass Quote Mmp Unfrozen Message */
static unsigned
dissect_deribit_ordersapi_mass_quote_mmp_unfrozen(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_exec_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_mmp_group_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_correlation_id_optional(tvb, pinfo, tree, offset);

    return offset;
}

/* Orders Mmp Unfrozen Message */
static unsigned
dissect_deribit_ordersapi_orders_mmp_unfrozen(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_exec_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_currency_pair_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_correlation_id_optional(tvb, pinfo, tree, offset);

    return offset;
}

/* Logon Message V14 */
static unsigned
dissect_deribit_ordersapi_logon_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_client_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_secret(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_reset_seq_num(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_schema_version(tvb, pinfo, tree, offset);

    return offset;
}

/* New Order Response Message V14 */
static unsigned
dissect_deribit_ordersapi_new_order_response_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_exec_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_client_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_price(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_quantity(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_total_filled(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_visible_qty(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_receive_time(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_side(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_status(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_cancel_reason(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_new_order_response_message_fills_groups(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_new_order_response_message_legs_groups(tvb, pinfo, tree, offset);

    return offset;
}

/* Cancel Order Response Message V14 */
static unsigned
dissect_deribit_ordersapi_cancel_order_response_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_exec_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_client_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_receive_time(tvb, pinfo, tree, offset);

    return offset;
}

/* Logon Message V13 */
static unsigned
dissect_deribit_ordersapi_logon_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_client_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_secret(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_reset_seq_num(tvb, pinfo, tree, offset);

    return offset;
}

/* Logon Conf Message V13 */
static unsigned
dissect_deribit_ordersapi_logon_conf_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_heartbeat_interval_seconds(tvb, pinfo, tree, offset);

    return offset;
}

/* New Order Response Message V13 */
static unsigned
dissect_deribit_ordersapi_new_order_response_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_exec_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_client_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_price(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_quantity(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_total_filled(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_visible_qty(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_receive_time(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_side(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_status(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_cancel_reason(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_new_order_response_message_fills_groups(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_new_order_response_message_legs_groups(tvb, pinfo, tree, offset);

    return offset;
}

/* Cancel Order Response Message V13 */
static unsigned
dissect_deribit_ordersapi_cancel_order_response_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_exec_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_client_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_receive_time(tvb, pinfo, tree, offset);

    return offset;
}

/* Logon Message V10 */
static unsigned
dissect_deribit_ordersapi_logon_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_client_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_secret(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_reset_seq_num(tvb, pinfo, tree, offset);

    return offset;
}

/* Logon Conf Message V10 */
static unsigned
dissect_deribit_ordersapi_logon_conf_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_heartbeat_interval_seconds(tvb, pinfo, tree, offset);

    return offset;
}

/* New Order Request Message V10 */
static unsigned
dissect_deribit_ordersapi_new_order_request_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_client_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_price(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_quantity(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_show_qty(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_self_match_prevention_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_side(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_time_in_force(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_flags_order_flags_v10(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_self_trading_mode(tvb, pinfo, tree, offset);

    return offset;
}

/* Mass Quote Request Message V10 */
static unsigned
dissect_deribit_ordersapi_mass_quote_request_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_quote_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_mmp_group_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_self_match_prevention_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_flags_mass_quote_flags(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_mass_quote_request_message_quotes_groups_v10(tvb, pinfo, tree, offset);

    return offset;
}

/* Mass Quote Request Message quotes Groups */
static unsigned
dissect_deribit_ordersapi_mass_quote_request_message_quotes_groups_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_mass_quote_request_message_quotes_groups_v10, &item, "Mass Quote Request Message quotes Groups");
    }

    unsigned start = offset;

    offset = dissect_deribit_ordersapi_group_size_encoding(tvb, pinfo, group, offset);

    /* Mass Quote Request Message quotes Group: Num In Group entries */
    uint32_t num_in_group = tvb_get_letohs(tvb, start + 2);

    for (uint32_t index = 0; index < num_in_group; index++) {
        offset = dissect_deribit_ordersapi_mass_quote_request_message_quotes_group_v10(tvb, pinfo, group, offset, index + 1);
    }

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Mass Quote Request Message quotes Group */
static unsigned
dissect_deribit_ordersapi_mass_quote_request_message_quotes_group_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t index)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (deribit_ordersapi_show_structs) {
        group = deribit_ordersapi_pref_show_indexes
            ? proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_deribit_ordersapi_mass_quote_request_message_quotes_group_v10, &item, "Mass Quote Request Message quotes Group %u", index)
            : proto_tree_add_subtree(tree, tvb, offset, -1, ett_deribit_ordersapi_mass_quote_request_message_quotes_group_v10, &item, "Mass Quote Request Message quotes Group");
    }

    unsigned start = offset;

    offset = parse_deribit_ordersapi_instrument_id(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_bid_price_optional(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_ask_price_optional(tvb, pinfo, group, offset);
    offset = dissect_deribit_ordersapi_bid_qty(tvb, pinfo, group, offset);
    offset = dissect_deribit_ordersapi_ask_qty(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_bid_flags_v10(tvb, pinfo, group, offset);
    offset = parse_deribit_ordersapi_ask_flags_v10(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* New Order Response Message V10 */
static unsigned
dissect_deribit_ordersapi_new_order_response_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_exec_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_client_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_price(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_quantity(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_total_filled(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_visible_qty(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_receive_time(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_side(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_status(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_cancel_reason(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_new_order_response_message_fills_groups(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_new_order_response_message_legs_groups(tvb, pinfo, tree, offset);

    return offset;
}

/* Cancel Order Response Message V10 */
static unsigned
dissect_deribit_ordersapi_cancel_order_response_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_exec_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_client_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_receive_time(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Placed Message V10 */
static unsigned
dissect_deribit_ordersapi_order_placed_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_exec_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_client_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_price(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_quantity(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_total_filled(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_visible_qty(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_status(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_cancel_reason(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_order_placed_message_fills_groups(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_order_placed_message_legs_groups(tvb, pinfo, tree, offset);

    return offset;
}

/* Logon Message V01 */
static unsigned
dissect_deribit_ordersapi_logon_v01(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_client_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_secret(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_reset_seq_num(tvb, pinfo, tree, offset);

    return offset;
}

/* Logon Conf Message V01 */
static unsigned
dissect_deribit_ordersapi_logon_conf_v01(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_heartbeat_interval_seconds(tvb, pinfo, tree, offset);

    return offset;
}

/* New Order Request Message V01 */
static unsigned
dissect_deribit_ordersapi_new_order_request_v01(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_client_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_price(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_quantity(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_show_qty(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_self_match_prevention_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_side(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_time_in_force(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_flags_order_flags_v10(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_self_trading_mode(tvb, pinfo, tree, offset);

    return offset;
}

/* Mass Quote Request Message V01 */
static unsigned
dissect_deribit_ordersapi_mass_quote_request_v01(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_quote_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_mmp_group_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_self_match_prevention_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_flags_mass_quote_flags(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_mass_quote_request_message_quotes_groups_v10(tvb, pinfo, tree, offset);

    return offset;
}

/* New Order Response Message V01 */
static unsigned
dissect_deribit_ordersapi_new_order_response_v01(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_exec_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_client_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_price(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_quantity(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_total_filled(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_visible_qty(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_receive_time(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_side(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_status(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_cancel_reason(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_new_order_response_message_fills_groups(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_new_order_response_message_legs_groups(tvb, pinfo, tree, offset);

    return offset;
}

/* Cancel Order Response Message V01 */
static unsigned
dissect_deribit_ordersapi_cancel_order_response_v01(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_exec_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_client_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_receive_time(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Placed Message V01 */
static unsigned
dissect_deribit_ordersapi_order_placed_v01(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_deribit_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_exec_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_client_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_order_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_price(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_quantity(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_total_filled(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_visible_qty(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_status(tvb, pinfo, tree, offset);
    offset = parse_deribit_ordersapi_cancel_reason(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_order_placed_message_fills_groups(tvb, pinfo, tree, offset);
    offset = dissect_deribit_ordersapi_order_placed_message_legs_groups(tvb, pinfo, tree, offset);

    return offset;
}

/*
 * Deribit OrdersApi Parse Trees, a dispatch per distinct branch definition
 */

static const value_string deribit_ordersapi_messages[] = {
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGON, "Logon Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGON_CONF, "Logon Conf Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGOUT, "Logout Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGGED_OUT, "Logged Out Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_HEARTBEAT, "Heartbeat Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_TEST_REQUEST, "Test Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_RESEND_REQUEST, "Resend Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_GAP_FILL, "Gap Fill Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_REJECT, "Reject Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_NEW_ORDER_REQUEST, "New Order Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_AMEND_ORDER_REQUEST, "Amend Order Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_REQUEST, "Cancel Order Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_BY_ID_REQUEST, "Cancel Order By Id Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_REQUEST, "Mass Quote Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_REQUEST, "Mass Cancel Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_CANCEL_REQUEST, "Mass Quote Cancel Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_MASS_QUOTE_MMP_STATUS_REQUEST, "Get Mass Quote Mmp Status Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_ORDERS_MMP_STATUS_REQUEST, "Get Orders Mmp Status Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_NEW_ORDER_RESPONSE, "New Order Response Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_NEW_ORDER_REJECT, "New Order Reject Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_AMEND_ORDER_RESPONSE, "Amend Order Response Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_AMEND_ORDER_REJECT, "Amend Order Reject Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_RESPONSE, "Cancel Order Response Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_REJECT, "Cancel Order Reject Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_RESPONSE, "Mass Quote Response Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_REJECT, "Mass Quote Reject Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_RESPONSE, "Mass Cancel Response Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_REJECT, "Mass Cancel Reject Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_MASS_QUOTE_MMP_STATUS_RESPONSE, "Get Mass Quote Mmp Status Response Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_MASS_QUOTE_MMP_STATUS_REJECT, "Get Mass Quote Mmp Status Reject Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_ORDERS_MMP_STATUS_RESPONSE, "Get Orders Mmp Status Response Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_ORDERS_MMP_STATUS_REJECT, "Get Orders Mmp Status Reject Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDER_FILLED, "Order Filled Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDERS_CANCELED, "Orders Canceled Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDER_PLACED, "Order Placed Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_ORDERS_PLACED, "Mass Quote Orders Placed Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_MMP_TRIGGERED, "Mass Quote Mmp Triggered Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDERS_MMP_TRIGGERED, "Orders Mmp Triggered Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_MMP_UNFROZEN, "Mass Quote Mmp Unfrozen Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDERS_MMP_UNFROZEN, "Orders Mmp Unfrozen Message" },
    { 0, NULL }
};

/* Payload: dispatch on template_id */
static unsigned
dissect_deribit_ordersapi_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, template_id, deribit_ordersapi_messages, "Unknown (%u)"));

    switch (template_id) {
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGON:
        return dissect_deribit_ordersapi_logon(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGON_CONF:
        return dissect_deribit_ordersapi_logon_conf(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGOUT:
        return dissect_deribit_ordersapi_logout(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGGED_OUT:
        return dissect_deribit_ordersapi_logged_out(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_HEARTBEAT:
        return dissect_deribit_ordersapi_heartbeat(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_TEST_REQUEST:
        return dissect_deribit_ordersapi_test_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_RESEND_REQUEST:
        return dissect_deribit_ordersapi_resend_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_GAP_FILL:
        return dissect_deribit_ordersapi_gap_fill(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_REJECT:
        return dissect_deribit_ordersapi_reject(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_NEW_ORDER_REQUEST:
        return dissect_deribit_ordersapi_new_order_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_AMEND_ORDER_REQUEST:
        return dissect_deribit_ordersapi_amend_order_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_REQUEST:
        return dissect_deribit_ordersapi_cancel_order_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_BY_ID_REQUEST:
        return dissect_deribit_ordersapi_cancel_order_by_id_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_REQUEST:
        return dissect_deribit_ordersapi_mass_quote_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_REQUEST:
        return dissect_deribit_ordersapi_mass_cancel_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_CANCEL_REQUEST:
        return dissect_deribit_ordersapi_mass_quote_cancel_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_MASS_QUOTE_MMP_STATUS_REQUEST:
        return dissect_deribit_ordersapi_get_mass_quote_mmp_status_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_ORDERS_MMP_STATUS_REQUEST:
        return dissect_deribit_ordersapi_get_orders_mmp_status_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_NEW_ORDER_RESPONSE:
        return dissect_deribit_ordersapi_new_order_response(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_NEW_ORDER_REJECT:
        return dissect_deribit_ordersapi_new_order_reject(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_AMEND_ORDER_RESPONSE:
        return dissect_deribit_ordersapi_amend_order_response(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_AMEND_ORDER_REJECT:
        return dissect_deribit_ordersapi_amend_order_reject(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_RESPONSE:
        return dissect_deribit_ordersapi_cancel_order_response(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_REJECT:
        return dissect_deribit_ordersapi_cancel_order_reject(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_RESPONSE:
        return dissect_deribit_ordersapi_mass_quote_response(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_REJECT:
        return dissect_deribit_ordersapi_mass_quote_reject(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_RESPONSE:
        return dissect_deribit_ordersapi_mass_cancel_response(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_REJECT:
        return dissect_deribit_ordersapi_mass_cancel_reject(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_MASS_QUOTE_MMP_STATUS_RESPONSE:
        return dissect_deribit_ordersapi_get_mass_quote_mmp_status_response(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_MASS_QUOTE_MMP_STATUS_REJECT:
        return dissect_deribit_ordersapi_get_mass_quote_mmp_status_reject(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_ORDERS_MMP_STATUS_RESPONSE:
        return dissect_deribit_ordersapi_get_orders_mmp_status_response(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_ORDERS_MMP_STATUS_REJECT:
        return dissect_deribit_ordersapi_get_orders_mmp_status_reject(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDER_FILLED:
        return dissect_deribit_ordersapi_order_filled(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDERS_CANCELED:
        return dissect_deribit_ordersapi_orders_canceled(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDER_PLACED:
        return dissect_deribit_ordersapi_order_placed(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_ORDERS_PLACED:
        return dissect_deribit_ordersapi_mass_quote_orders_placed(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_MMP_TRIGGERED:
        return dissect_deribit_ordersapi_mass_quote_mmp_triggered(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDERS_MMP_TRIGGERED:
        return dissect_deribit_ordersapi_orders_mmp_triggered(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_MMP_UNFROZEN:
        return dissect_deribit_ordersapi_mass_quote_mmp_unfrozen(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDERS_MMP_UNFROZEN:
        return dissect_deribit_ordersapi_orders_mmp_unfrozen(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string deribit_ordersapi_messages_v14[] = {
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGON, "Logon Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGON_CONF, "Logon Conf Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGOUT, "Logout Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGGED_OUT, "Logged Out Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_HEARTBEAT, "Heartbeat Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_TEST_REQUEST, "Test Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_RESEND_REQUEST, "Resend Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_GAP_FILL, "Gap Fill Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_REJECT, "Reject Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_NEW_ORDER_REQUEST, "New Order Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_AMEND_ORDER_REQUEST, "Amend Order Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_REQUEST, "Cancel Order Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_BY_ID_REQUEST, "Cancel Order By Id Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_REQUEST, "Mass Quote Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_REQUEST, "Mass Cancel Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_CANCEL_REQUEST, "Mass Quote Cancel Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_MASS_QUOTE_MMP_STATUS_REQUEST, "Get Mass Quote Mmp Status Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_ORDERS_MMP_STATUS_REQUEST, "Get Orders Mmp Status Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_NEW_ORDER_RESPONSE, "New Order Response Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_NEW_ORDER_REJECT, "New Order Reject Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_AMEND_ORDER_RESPONSE, "Amend Order Response Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_AMEND_ORDER_REJECT, "Amend Order Reject Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_RESPONSE, "Cancel Order Response Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_REJECT, "Cancel Order Reject Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_RESPONSE, "Mass Quote Response Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_REJECT, "Mass Quote Reject Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_RESPONSE, "Mass Cancel Response Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_REJECT, "Mass Cancel Reject Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_MASS_QUOTE_MMP_STATUS_RESPONSE, "Get Mass Quote Mmp Status Response Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_MASS_QUOTE_MMP_STATUS_REJECT, "Get Mass Quote Mmp Status Reject Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_ORDERS_MMP_STATUS_RESPONSE, "Get Orders Mmp Status Response Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_ORDERS_MMP_STATUS_REJECT, "Get Orders Mmp Status Reject Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDER_FILLED, "Order Filled Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDERS_CANCELED, "Orders Canceled Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDER_PLACED, "Order Placed Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_ORDERS_PLACED, "Mass Quote Orders Placed Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_MMP_TRIGGERED, "Mass Quote Mmp Triggered Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDERS_MMP_TRIGGERED, "Orders Mmp Triggered Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_MMP_UNFROZEN, "Mass Quote Mmp Unfrozen Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDERS_MMP_UNFROZEN, "Orders Mmp Unfrozen Message" },
    { 0, NULL }
};

/* Payload: dispatch on template_id */
static unsigned
dissect_deribit_ordersapi_payload_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, template_id, deribit_ordersapi_messages_v14, "Unknown (%u)"));

    switch (template_id) {
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGON:
        return dissect_deribit_ordersapi_logon_v14(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGON_CONF:
        return dissect_deribit_ordersapi_logon_conf(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGOUT:
        return dissect_deribit_ordersapi_logout(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGGED_OUT:
        return dissect_deribit_ordersapi_logged_out(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_HEARTBEAT:
        return dissect_deribit_ordersapi_heartbeat(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_TEST_REQUEST:
        return dissect_deribit_ordersapi_test_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_RESEND_REQUEST:
        return dissect_deribit_ordersapi_resend_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_GAP_FILL:
        return dissect_deribit_ordersapi_gap_fill(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_REJECT:
        return dissect_deribit_ordersapi_reject(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_NEW_ORDER_REQUEST:
        return dissect_deribit_ordersapi_new_order_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_AMEND_ORDER_REQUEST:
        return dissect_deribit_ordersapi_amend_order_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_REQUEST:
        return dissect_deribit_ordersapi_cancel_order_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_BY_ID_REQUEST:
        return dissect_deribit_ordersapi_cancel_order_by_id_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_REQUEST:
        return dissect_deribit_ordersapi_mass_quote_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_REQUEST:
        return dissect_deribit_ordersapi_mass_cancel_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_CANCEL_REQUEST:
        return dissect_deribit_ordersapi_mass_quote_cancel_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_MASS_QUOTE_MMP_STATUS_REQUEST:
        return dissect_deribit_ordersapi_get_mass_quote_mmp_status_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_ORDERS_MMP_STATUS_REQUEST:
        return dissect_deribit_ordersapi_get_orders_mmp_status_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_NEW_ORDER_RESPONSE:
        return dissect_deribit_ordersapi_new_order_response_v14(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_NEW_ORDER_REJECT:
        return dissect_deribit_ordersapi_new_order_reject(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_AMEND_ORDER_RESPONSE:
        return dissect_deribit_ordersapi_amend_order_response(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_AMEND_ORDER_REJECT:
        return dissect_deribit_ordersapi_amend_order_reject(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_RESPONSE:
        return dissect_deribit_ordersapi_cancel_order_response_v14(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_REJECT:
        return dissect_deribit_ordersapi_cancel_order_reject(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_RESPONSE:
        return dissect_deribit_ordersapi_mass_quote_response(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_REJECT:
        return dissect_deribit_ordersapi_mass_quote_reject(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_RESPONSE:
        return dissect_deribit_ordersapi_mass_cancel_response(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_REJECT:
        return dissect_deribit_ordersapi_mass_cancel_reject(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_MASS_QUOTE_MMP_STATUS_RESPONSE:
        return dissect_deribit_ordersapi_get_mass_quote_mmp_status_response(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_MASS_QUOTE_MMP_STATUS_REJECT:
        return dissect_deribit_ordersapi_get_mass_quote_mmp_status_reject(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_ORDERS_MMP_STATUS_RESPONSE:
        return dissect_deribit_ordersapi_get_orders_mmp_status_response(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_ORDERS_MMP_STATUS_REJECT:
        return dissect_deribit_ordersapi_get_orders_mmp_status_reject(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDER_FILLED:
        return dissect_deribit_ordersapi_order_filled(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDERS_CANCELED:
        return dissect_deribit_ordersapi_orders_canceled(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDER_PLACED:
        return dissect_deribit_ordersapi_order_placed(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_ORDERS_PLACED:
        return dissect_deribit_ordersapi_mass_quote_orders_placed(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_MMP_TRIGGERED:
        return dissect_deribit_ordersapi_mass_quote_mmp_triggered(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDERS_MMP_TRIGGERED:
        return dissect_deribit_ordersapi_orders_mmp_triggered(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_MMP_UNFROZEN:
        return dissect_deribit_ordersapi_mass_quote_mmp_unfrozen(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDERS_MMP_UNFROZEN:
        return dissect_deribit_ordersapi_orders_mmp_unfrozen(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string deribit_ordersapi_messages_v13[] = {
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGON, "Logon Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGON_CONF, "Logon Conf Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGOUT, "Logout Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGGED_OUT, "Logged Out Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_HEARTBEAT, "Heartbeat Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_TEST_REQUEST, "Test Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_RESEND_REQUEST, "Resend Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_GAP_FILL, "Gap Fill Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_REJECT, "Reject Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_NEW_ORDER_REQUEST, "New Order Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_AMEND_ORDER_REQUEST, "Amend Order Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_REQUEST, "Cancel Order Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_BY_ID_REQUEST, "Cancel Order By Id Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_REQUEST, "Mass Quote Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_REQUEST, "Mass Cancel Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_CANCEL_REQUEST, "Mass Quote Cancel Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_MASS_QUOTE_MMP_STATUS_REQUEST, "Get Mass Quote Mmp Status Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_ORDERS_MMP_STATUS_REQUEST, "Get Orders Mmp Status Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_NEW_ORDER_RESPONSE, "New Order Response Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_NEW_ORDER_REJECT, "New Order Reject Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_AMEND_ORDER_RESPONSE, "Amend Order Response Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_AMEND_ORDER_REJECT, "Amend Order Reject Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_RESPONSE, "Cancel Order Response Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_REJECT, "Cancel Order Reject Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_RESPONSE, "Mass Quote Response Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_REJECT, "Mass Quote Reject Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_RESPONSE, "Mass Cancel Response Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_REJECT, "Mass Cancel Reject Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_MASS_QUOTE_MMP_STATUS_RESPONSE, "Get Mass Quote Mmp Status Response Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_MASS_QUOTE_MMP_STATUS_REJECT, "Get Mass Quote Mmp Status Reject Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_ORDERS_MMP_STATUS_RESPONSE, "Get Orders Mmp Status Response Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_ORDERS_MMP_STATUS_REJECT, "Get Orders Mmp Status Reject Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDER_FILLED, "Order Filled Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDERS_CANCELED, "Orders Canceled Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDER_PLACED, "Order Placed Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_ORDERS_PLACED, "Mass Quote Orders Placed Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_MMP_TRIGGERED, "Mass Quote Mmp Triggered Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDERS_MMP_TRIGGERED, "Orders Mmp Triggered Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_MMP_UNFROZEN, "Mass Quote Mmp Unfrozen Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDERS_MMP_UNFROZEN, "Orders Mmp Unfrozen Message" },
    { 0, NULL }
};

/* Payload: dispatch on template_id */
static unsigned
dissect_deribit_ordersapi_payload_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, template_id, deribit_ordersapi_messages_v13, "Unknown (%u)"));

    switch (template_id) {
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGON:
        return dissect_deribit_ordersapi_logon_v13(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGON_CONF:
        return dissect_deribit_ordersapi_logon_conf_v13(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGOUT:
        return dissect_deribit_ordersapi_logout(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGGED_OUT:
        return dissect_deribit_ordersapi_logged_out(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_HEARTBEAT:
        return dissect_deribit_ordersapi_heartbeat(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_TEST_REQUEST:
        return dissect_deribit_ordersapi_test_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_RESEND_REQUEST:
        return dissect_deribit_ordersapi_resend_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_GAP_FILL:
        return dissect_deribit_ordersapi_gap_fill(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_REJECT:
        return dissect_deribit_ordersapi_reject(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_NEW_ORDER_REQUEST:
        return dissect_deribit_ordersapi_new_order_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_AMEND_ORDER_REQUEST:
        return dissect_deribit_ordersapi_amend_order_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_REQUEST:
        return dissect_deribit_ordersapi_cancel_order_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_BY_ID_REQUEST:
        return dissect_deribit_ordersapi_cancel_order_by_id_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_REQUEST:
        return dissect_deribit_ordersapi_mass_quote_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_REQUEST:
        return dissect_deribit_ordersapi_mass_cancel_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_CANCEL_REQUEST:
        return dissect_deribit_ordersapi_mass_quote_cancel_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_MASS_QUOTE_MMP_STATUS_REQUEST:
        return dissect_deribit_ordersapi_get_mass_quote_mmp_status_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_ORDERS_MMP_STATUS_REQUEST:
        return dissect_deribit_ordersapi_get_orders_mmp_status_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_NEW_ORDER_RESPONSE:
        return dissect_deribit_ordersapi_new_order_response_v13(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_NEW_ORDER_REJECT:
        return dissect_deribit_ordersapi_new_order_reject(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_AMEND_ORDER_RESPONSE:
        return dissect_deribit_ordersapi_amend_order_response(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_AMEND_ORDER_REJECT:
        return dissect_deribit_ordersapi_amend_order_reject(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_RESPONSE:
        return dissect_deribit_ordersapi_cancel_order_response_v13(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_REJECT:
        return dissect_deribit_ordersapi_cancel_order_reject(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_RESPONSE:
        return dissect_deribit_ordersapi_mass_quote_response(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_REJECT:
        return dissect_deribit_ordersapi_mass_quote_reject(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_RESPONSE:
        return dissect_deribit_ordersapi_mass_cancel_response(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_REJECT:
        return dissect_deribit_ordersapi_mass_cancel_reject(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_MASS_QUOTE_MMP_STATUS_RESPONSE:
        return dissect_deribit_ordersapi_get_mass_quote_mmp_status_response(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_MASS_QUOTE_MMP_STATUS_REJECT:
        return dissect_deribit_ordersapi_get_mass_quote_mmp_status_reject(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_ORDERS_MMP_STATUS_RESPONSE:
        return dissect_deribit_ordersapi_get_orders_mmp_status_response(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_ORDERS_MMP_STATUS_REJECT:
        return dissect_deribit_ordersapi_get_orders_mmp_status_reject(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDER_FILLED:
        return dissect_deribit_ordersapi_order_filled(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDERS_CANCELED:
        return dissect_deribit_ordersapi_orders_canceled(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDER_PLACED:
        return dissect_deribit_ordersapi_order_placed(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_ORDERS_PLACED:
        return dissect_deribit_ordersapi_mass_quote_orders_placed(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_MMP_TRIGGERED:
        return dissect_deribit_ordersapi_mass_quote_mmp_triggered(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDERS_MMP_TRIGGERED:
        return dissect_deribit_ordersapi_orders_mmp_triggered(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_MMP_UNFROZEN:
        return dissect_deribit_ordersapi_mass_quote_mmp_unfrozen(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDERS_MMP_UNFROZEN:
        return dissect_deribit_ordersapi_orders_mmp_unfrozen(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string deribit_ordersapi_messages_v10[] = {
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGON, "Logon Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGON_CONF, "Logon Conf Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGOUT, "Logout Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGGED_OUT, "Logged Out Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_HEARTBEAT, "Heartbeat Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_TEST_REQUEST, "Test Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_RESEND_REQUEST, "Resend Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_GAP_FILL, "Gap Fill Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_REJECT, "Reject Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_NEW_ORDER_REQUEST, "New Order Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_AMEND_ORDER_REQUEST, "Amend Order Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_REQUEST, "Cancel Order Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_REQUEST, "Mass Quote Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_REQUEST, "Mass Cancel Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_CANCEL_REQUEST, "Mass Quote Cancel Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_NEW_ORDER_RESPONSE, "New Order Response Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_NEW_ORDER_REJECT, "New Order Reject Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_AMEND_ORDER_RESPONSE, "Amend Order Response Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_AMEND_ORDER_REJECT, "Amend Order Reject Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_RESPONSE, "Cancel Order Response Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_REJECT, "Cancel Order Reject Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_RESPONSE, "Mass Quote Response Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_REJECT, "Mass Quote Reject Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_RESPONSE, "Mass Cancel Response Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_REJECT, "Mass Cancel Reject Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDER_FILLED, "Order Filled Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDERS_CANCELED, "Orders Canceled Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDER_PLACED, "Order Placed Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_ORDERS_PLACED, "Mass Quote Orders Placed Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_MMP_TRIGGERED, "Mass Quote Mmp Triggered Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDERS_MMP_TRIGGERED, "Orders Mmp Triggered Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_MMP_UNFROZEN, "Mass Quote Mmp Unfrozen Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDERS_MMP_UNFROZEN, "Orders Mmp Unfrozen Message" },
    { 0, NULL }
};

/* Payload: dispatch on template_id */
static unsigned
dissect_deribit_ordersapi_payload_v10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, template_id, deribit_ordersapi_messages_v10, "Unknown (%u)"));

    switch (template_id) {
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGON:
        return dissect_deribit_ordersapi_logon_v10(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGON_CONF:
        return dissect_deribit_ordersapi_logon_conf_v10(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGOUT:
        return dissect_deribit_ordersapi_logout(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGGED_OUT:
        return dissect_deribit_ordersapi_logged_out(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_HEARTBEAT:
        return dissect_deribit_ordersapi_heartbeat(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_TEST_REQUEST:
        return dissect_deribit_ordersapi_test_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_RESEND_REQUEST:
        return dissect_deribit_ordersapi_resend_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_GAP_FILL:
        return dissect_deribit_ordersapi_gap_fill(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_REJECT:
        return dissect_deribit_ordersapi_reject(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_NEW_ORDER_REQUEST:
        return dissect_deribit_ordersapi_new_order_request_v10(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_AMEND_ORDER_REQUEST:
        return dissect_deribit_ordersapi_amend_order_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_REQUEST:
        return dissect_deribit_ordersapi_cancel_order_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_REQUEST:
        return dissect_deribit_ordersapi_mass_quote_request_v10(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_REQUEST:
        return dissect_deribit_ordersapi_mass_cancel_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_CANCEL_REQUEST:
        return dissect_deribit_ordersapi_mass_quote_cancel_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_NEW_ORDER_RESPONSE:
        return dissect_deribit_ordersapi_new_order_response_v10(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_NEW_ORDER_REJECT:
        return dissect_deribit_ordersapi_new_order_reject(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_AMEND_ORDER_RESPONSE:
        return dissect_deribit_ordersapi_amend_order_response(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_AMEND_ORDER_REJECT:
        return dissect_deribit_ordersapi_amend_order_reject(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_RESPONSE:
        return dissect_deribit_ordersapi_cancel_order_response_v10(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_REJECT:
        return dissect_deribit_ordersapi_cancel_order_reject(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_RESPONSE:
        return dissect_deribit_ordersapi_mass_quote_response(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_REJECT:
        return dissect_deribit_ordersapi_mass_quote_reject(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_RESPONSE:
        return dissect_deribit_ordersapi_mass_cancel_response(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_REJECT:
        return dissect_deribit_ordersapi_mass_cancel_reject(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDER_FILLED:
        return dissect_deribit_ordersapi_order_filled(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDERS_CANCELED:
        return dissect_deribit_ordersapi_orders_canceled(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDER_PLACED:
        return dissect_deribit_ordersapi_order_placed_v10(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_ORDERS_PLACED:
        return dissect_deribit_ordersapi_mass_quote_orders_placed(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_MMP_TRIGGERED:
        return dissect_deribit_ordersapi_mass_quote_mmp_triggered(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDERS_MMP_TRIGGERED:
        return dissect_deribit_ordersapi_orders_mmp_triggered(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_MMP_UNFROZEN:
        return dissect_deribit_ordersapi_mass_quote_mmp_unfrozen(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDERS_MMP_UNFROZEN:
        return dissect_deribit_ordersapi_orders_mmp_unfrozen(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string deribit_ordersapi_messages_v01[] = {
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGON, "Logon Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGON_CONF, "Logon Conf Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGOUT, "Logout Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGGED_OUT, "Logged Out Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_HEARTBEAT, "Heartbeat Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_TEST_REQUEST, "Test Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_RESEND_REQUEST, "Resend Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_GAP_FILL, "Gap Fill Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_REJECT, "Reject Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_NEW_ORDER_REQUEST, "New Order Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_AMEND_ORDER_REQUEST, "Amend Order Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_REQUEST, "Cancel Order Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_REQUEST, "Mass Quote Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_REQUEST, "Mass Cancel Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_CANCEL_REQUEST, "Mass Quote Cancel Request Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_NEW_ORDER_RESPONSE, "New Order Response Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_NEW_ORDER_REJECT, "New Order Reject Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_AMEND_ORDER_RESPONSE, "Amend Order Response Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_AMEND_ORDER_REJECT, "Amend Order Reject Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_RESPONSE, "Cancel Order Response Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_REJECT, "Cancel Order Reject Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_RESPONSE, "Mass Quote Response Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_REJECT, "Mass Quote Reject Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_RESPONSE, "Mass Cancel Response Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_REJECT, "Mass Cancel Reject Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDER_FILLED, "Order Filled Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDERS_CANCELED, "Orders Canceled Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDER_PLACED, "Order Placed Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_ORDERS_PLACED, "Mass Quote Orders Placed Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_MMP_TRIGGERED, "Mass Quote Mmp Triggered Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDERS_MMP_TRIGGERED, "Orders Mmp Triggered Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_MMP_UNFROZEN, "Mass Quote Mmp Unfrozen Message" },
    { DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDERS_MMP_UNFROZEN, "Orders Mmp Unfrozen Message" },
    { 0, NULL }
};

/* Payload: dispatch on template_id */
static unsigned
dissect_deribit_ordersapi_payload_v01(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, template_id, deribit_ordersapi_messages_v01, "Unknown (%u)"));

    switch (template_id) {
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGON:
        return dissect_deribit_ordersapi_logon_v01(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGON_CONF:
        return dissect_deribit_ordersapi_logon_conf_v01(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGOUT:
        return dissect_deribit_ordersapi_logout(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGGED_OUT:
        return dissect_deribit_ordersapi_logged_out(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_HEARTBEAT:
        return dissect_deribit_ordersapi_heartbeat(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_TEST_REQUEST:
        return dissect_deribit_ordersapi_test_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_RESEND_REQUEST:
        return dissect_deribit_ordersapi_resend_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_GAP_FILL:
        return dissect_deribit_ordersapi_gap_fill(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_REJECT:
        return dissect_deribit_ordersapi_reject(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_NEW_ORDER_REQUEST:
        return dissect_deribit_ordersapi_new_order_request_v01(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_AMEND_ORDER_REQUEST:
        return dissect_deribit_ordersapi_amend_order_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_REQUEST:
        return dissect_deribit_ordersapi_cancel_order_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_REQUEST:
        return dissect_deribit_ordersapi_mass_quote_request_v01(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_REQUEST:
        return dissect_deribit_ordersapi_mass_cancel_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_CANCEL_REQUEST:
        return dissect_deribit_ordersapi_mass_quote_cancel_request(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_NEW_ORDER_RESPONSE:
        return dissect_deribit_ordersapi_new_order_response_v01(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_NEW_ORDER_REJECT:
        return dissect_deribit_ordersapi_new_order_reject(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_AMEND_ORDER_RESPONSE:
        return dissect_deribit_ordersapi_amend_order_response(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_AMEND_ORDER_REJECT:
        return dissect_deribit_ordersapi_amend_order_reject(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_RESPONSE:
        return dissect_deribit_ordersapi_cancel_order_response_v01(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_REJECT:
        return dissect_deribit_ordersapi_cancel_order_reject(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_RESPONSE:
        return dissect_deribit_ordersapi_mass_quote_response(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_REJECT:
        return dissect_deribit_ordersapi_mass_quote_reject(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_RESPONSE:
        return dissect_deribit_ordersapi_mass_cancel_response(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_REJECT:
        return dissect_deribit_ordersapi_mass_cancel_reject(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDER_FILLED:
        return dissect_deribit_ordersapi_order_filled(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDERS_CANCELED:
        return dissect_deribit_ordersapi_orders_canceled(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDER_PLACED:
        return dissect_deribit_ordersapi_order_placed_v01(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_ORDERS_PLACED:
        return dissect_deribit_ordersapi_mass_quote_orders_placed(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_MMP_TRIGGERED:
        return dissect_deribit_ordersapi_mass_quote_mmp_triggered(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDERS_MMP_TRIGGERED:
        return dissect_deribit_ordersapi_orders_mmp_triggered(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_MMP_UNFROZEN:
        return dissect_deribit_ordersapi_mass_quote_mmp_unfrozen(tvb, pinfo, tree, offset);
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDERS_MMP_UNFROZEN:
        return dissect_deribit_ordersapi_orders_mmp_unfrozen(tvb, pinfo, tree, offset);
    }

    return offset;
}

/* Show preference of the dispatched message */
static bool
deribit_ordersapi_show(uint32_t template_id)
{
    switch (template_id) {
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGON:
        return deribit_ordersapi_show_application_messages;
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGON_CONF:
        return deribit_ordersapi_show_application_messages;
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGOUT:
        return deribit_ordersapi_show_application_messages;
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_LOGGED_OUT:
        return deribit_ordersapi_show_application_messages;
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_HEARTBEAT:
        return deribit_ordersapi_show_application_messages;
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_TEST_REQUEST:
        return deribit_ordersapi_show_application_messages;
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_RESEND_REQUEST:
        return deribit_ordersapi_show_application_messages;
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_GAP_FILL:
        return deribit_ordersapi_show_application_messages;
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_REJECT:
        return deribit_ordersapi_show_application_messages;
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_NEW_ORDER_REQUEST:
        return deribit_ordersapi_show_application_messages;
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_AMEND_ORDER_REQUEST:
        return deribit_ordersapi_show_application_messages;
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_REQUEST:
        return deribit_ordersapi_show_application_messages;
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_BY_ID_REQUEST:
        return deribit_ordersapi_show_application_messages;
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_REQUEST:
        return deribit_ordersapi_show_application_messages;
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_REQUEST:
        return deribit_ordersapi_show_application_messages;
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_CANCEL_REQUEST:
        return deribit_ordersapi_show_application_messages;
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_MASS_QUOTE_MMP_STATUS_REQUEST:
        return deribit_ordersapi_show_application_messages;
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_ORDERS_MMP_STATUS_REQUEST:
        return deribit_ordersapi_show_application_messages;
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_NEW_ORDER_RESPONSE:
        return deribit_ordersapi_show_application_messages;
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_NEW_ORDER_REJECT:
        return deribit_ordersapi_show_application_messages;
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_AMEND_ORDER_RESPONSE:
        return deribit_ordersapi_show_application_messages;
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_AMEND_ORDER_REJECT:
        return deribit_ordersapi_show_application_messages;
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_RESPONSE:
        return deribit_ordersapi_show_application_messages;
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_REJECT:
        return deribit_ordersapi_show_application_messages;
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_RESPONSE:
        return deribit_ordersapi_show_application_messages;
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_REJECT:
        return deribit_ordersapi_show_application_messages;
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_RESPONSE:
        return deribit_ordersapi_show_application_messages;
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_REJECT:
        return deribit_ordersapi_show_application_messages;
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_MASS_QUOTE_MMP_STATUS_RESPONSE:
        return deribit_ordersapi_show_application_messages;
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_MASS_QUOTE_MMP_STATUS_REJECT:
        return deribit_ordersapi_show_application_messages;
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_ORDERS_MMP_STATUS_RESPONSE:
        return deribit_ordersapi_show_application_messages;
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_GET_ORDERS_MMP_STATUS_REJECT:
        return deribit_ordersapi_show_application_messages;
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDER_FILLED:
        return deribit_ordersapi_show_application_messages;
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDERS_CANCELED:
        return deribit_ordersapi_show_application_messages;
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDER_PLACED:
        return deribit_ordersapi_show_application_messages;
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_ORDERS_PLACED:
        return deribit_ordersapi_show_application_messages;
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_MMP_TRIGGERED:
        return deribit_ordersapi_show_application_messages;
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDERS_MMP_TRIGGERED:
        return deribit_ordersapi_show_application_messages;
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_MASS_QUOTE_MMP_UNFROZEN:
        return deribit_ordersapi_show_application_messages;
    case DERIBIT_ORDERSAPI_TEMPLATE_ID_ORDERS_MMP_UNFROZEN:
        return deribit_ordersapi_show_application_messages;
    }

    return true;
}

typedef struct deribit_ordersapi_parse deribit_ordersapi_parse;

struct deribit_ordersapi_parse {
    const value_string *messages;
    unsigned (*dissect)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id);
};

static const deribit_ordersapi_parse deribit_ordersapi_parse_v15 = { deribit_ordersapi_messages, dissect_deribit_ordersapi_payload };
static const deribit_ordersapi_parse deribit_ordersapi_parse_v14 = { deribit_ordersapi_messages_v14, dissect_deribit_ordersapi_payload_v14 };
static const deribit_ordersapi_parse deribit_ordersapi_parse_v13 = { deribit_ordersapi_messages_v13, dissect_deribit_ordersapi_payload_v13 };
static const deribit_ordersapi_parse deribit_ordersapi_parse_v10 = { deribit_ordersapi_messages_v10, dissect_deribit_ordersapi_payload_v10 };
static const deribit_ordersapi_parse deribit_ordersapi_parse_v01 = { deribit_ordersapi_messages_v01, dissect_deribit_ordersapi_payload_v01 };

/* Parse tree of the selected version */
static const deribit_ordersapi_parse *
deribit_ordersapi_parse_for(int version)
{
    switch (version) {
    case DERIBIT_ORDERSAPI_VERSION_1_4:
        return &deribit_ordersapi_parse_v14;
    case DERIBIT_ORDERSAPI_VERSION_1_3:
        return &deribit_ordersapi_parse_v13;
    case DERIBIT_ORDERSAPI_VERSION_1_0:
        return &deribit_ordersapi_parse_v10;
    case DERIBIT_ORDERSAPI_VERSION_0_1:
        return &deribit_ordersapi_parse_v01;
    default:
        return &deribit_ordersapi_parse_v15;
    }
}

/* One length prefixed message, returns the consumed size */
static unsigned
dissect_deribit_ordersapi_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, const deribit_ordersapi_parse *parse)
{
    uint32_t message_length = tvb_get_letohs(tvb, offset + 2);
    uint32_t template_id = tvb_get_letohs(tvb, offset + 4);

    const char *name = val_to_str(pinfo->pool, template_id, parse->messages, "Unknown (%u)");

    proto_tree *message = deribit_ordersapi_show(template_id)
        ? proto_tree_add_subtree(tree, tvb, offset, message_length, ett_deribit_ordersapi_message, NULL, name)
        : tree;

    unsigned position = offset;

    position = dissect_deribit_ordersapi_message_header(tvb, pinfo, message, position);

    position = parse->dissect(tvb, pinfo, message, position, template_id);

    /* Padding: Tcp sbe alignment padding */
    uint32_t padding = message_length - (uint32_t)(position - offset);

    if (padding > 0) {
        proto_tree_add_item(message, hf_deribit_ordersapi_padding, tvb, position, padding, DERIBIT_ORDERSAPI_PADDING_ENCODING);
        position += padding;
    }

    /* The parsed fields must account for the declared length exactly */
    if (position != offset + message_length) {
        expert_add_info(pinfo, message, &ei_deribit_ordersapi_length);
    }

    return message_length;
}

/* Framed messages to the end of the stream, a partial
   frame asks the transport for its remaining bytes */
static unsigned
dissect_deribit_ordersapi_messages(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, const deribit_ordersapi_parse *parse)
{
    while (offset < tvb_reported_length(tvb)) {
        unsigned remaining = tvb_reported_length(tvb) - offset;

        if (remaining < 4) {
            pinfo->desegment_offset = (int)offset;
            pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            return offset;
        }

        unsigned frame = tvb_get_letohs(tvb, offset + 2);

        if (remaining < frame) {
            pinfo->desegment_offset = (int)offset;
            pinfo->desegment_len = frame - remaining;
            return offset;
        }

        offset += dissect_deribit_ordersapi_message(tvb, pinfo, tree, offset, parse);
    }

    return offset;
}

/* Packet: header then counted messages */
static int
dissect_deribit_ordersapi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, DERIBIT_ORDERSAPI_PROTOCOL_SHORT);
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *item = proto_tree_add_item(tree, proto_deribit_ordersapi, tvb, 0, -1, ENC_NA);
    proto_tree *packet = proto_item_add_subtree(item, ett_deribit_ordersapi);

    uint64_t seconds = (uint64_t)pinfo->abs_ts.secs;
    int version = deribit_ordersapi_version(seconds);

    proto_item_append_text(item, " %s", deribit_ordersapi_version_name(version));

    const deribit_ordersapi_parse *parse = deribit_ordersapi_parse_for(version);
    unsigned position = 0;

    position = dissect_deribit_ordersapi_messages(tvb, pinfo, packet, position, parse);

    return (int)position;
}

/* The fewest bytes any frame of the protocol holds, a header without messages */
#define DERIBIT_ORDERSAPI_MINIMUM_SIZE 32

/* The frame travels on a port the feed is assigned, the ports are the
   deployment's and held by preference */
static bool
deribit_ordersapi_heur_port(packet_info *pinfo)
{
    return value_is_in_range(deribit_ordersapi_pref_ports, pinfo->destport)
        || value_is_in_range(deribit_ordersapi_pref_ports, pinfo->srcport);
}

/* The first frame's declared length fits the stream */
static bool
deribit_ordersapi_heur_frame(tvbuff_t *tvb)
{
    int frame = (int)(tvb_get_letohs(tvb, 2));

    return frame >= DERIBIT_ORDERSAPI_HEADER_SIZE && frame <= (int)tvb_reported_length(tvb);
}

/* Does the frame pass every test of Packet? */
static bool
deribit_ordersapi_heur_accepts(tvbuff_t *tvb, packet_info *pinfo)
{
    if (!deribit_ordersapi_heur_port(pinfo)) {
        return false;
    }

    if (!deribit_ordersapi_heur_frame(tvb)) {
        return false;
    }

    return true;
}

/* Recognize the protocol by the port it travels on */
static bool
dissect_deribit_ordersapi_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (tvb_captured_length(tvb) < DERIBIT_ORDERSAPI_MINIMUM_SIZE) {
        return false;
    }

    if (!deribit_ordersapi_heur_accepts(tvb, pinfo)) {
        return false;
    }

    dissect_deribit_ordersapi(tvb, pinfo, tree, data);

    return true;
}

/*
 * Deribit OrdersApi Registration
 */

void
proto_register_deribit_ordersapi(void)
{
    static hf_register_info hf[] = {

        /* Fields */
        { &hf_deribit_ordersapi_ask_order_id,
            { DERIBIT_ORDERSAPI_ASK_ORDER_ID_NAME,
              DERIBIT_ORDERSAPI_ASK_ORDER_ID_FILTER,
              DERIBIT_ORDERSAPI_ASK_ORDER_ID_TYPE,
              DERIBIT_ORDERSAPI_ASK_ORDER_ID_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_ASK_ORDER_ID_MASK,
              DERIBIT_ORDERSAPI_ASK_ORDER_ID_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_ask_price,
            { DERIBIT_ORDERSAPI_ASK_PRICE_NAME,
              DERIBIT_ORDERSAPI_ASK_PRICE_FILTER,
              DERIBIT_ORDERSAPI_ASK_PRICE_TYPE,
              DERIBIT_ORDERSAPI_ASK_PRICE_DISPLAY,
              CF_FUNC(deribit_ordersapi_format_decimal_9_64),
              DERIBIT_ORDERSAPI_ASK_PRICE_MASK,
              DERIBIT_ORDERSAPI_ASK_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_ask_price_optional,
            { DERIBIT_ORDERSAPI_ASK_PRICE_OPTIONAL_NAME,
              DERIBIT_ORDERSAPI_ASK_PRICE_OPTIONAL_FILTER,
              DERIBIT_ORDERSAPI_ASK_PRICE_OPTIONAL_TYPE,
              DERIBIT_ORDERSAPI_ASK_PRICE_OPTIONAL_DISPLAY,
              CF_FUNC(deribit_ordersapi_format_decimal_9_64_nullable),
              DERIBIT_ORDERSAPI_ASK_PRICE_OPTIONAL_MASK,
              DERIBIT_ORDERSAPI_ASK_PRICE_OPTIONAL_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_ask_reject_reason,
            { DERIBIT_ORDERSAPI_ASK_REJECT_REASON_NAME,
              DERIBIT_ORDERSAPI_ASK_REJECT_REASON_FILTER,
              DERIBIT_ORDERSAPI_ASK_REJECT_REASON_TYPE,
              DERIBIT_ORDERSAPI_ASK_REJECT_REASON_DISPLAY,
              VALS(deribit_ordersapi_ask_reject_reason_vals),
              DERIBIT_ORDERSAPI_ASK_REJECT_REASON_MASK,
              DERIBIT_ORDERSAPI_ASK_REJECT_REASON_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_ask_status,
            { DERIBIT_ORDERSAPI_ASK_STATUS_NAME,
              DERIBIT_ORDERSAPI_ASK_STATUS_FILTER,
              DERIBIT_ORDERSAPI_ASK_STATUS_TYPE,
              DERIBIT_ORDERSAPI_ASK_STATUS_DISPLAY,
              VALS(deribit_ordersapi_ask_status_vals),
              DERIBIT_ORDERSAPI_ASK_STATUS_MASK,
              DERIBIT_ORDERSAPI_ASK_STATUS_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_bid_order_id,
            { DERIBIT_ORDERSAPI_BID_ORDER_ID_NAME,
              DERIBIT_ORDERSAPI_BID_ORDER_ID_FILTER,
              DERIBIT_ORDERSAPI_BID_ORDER_ID_TYPE,
              DERIBIT_ORDERSAPI_BID_ORDER_ID_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_BID_ORDER_ID_MASK,
              DERIBIT_ORDERSAPI_BID_ORDER_ID_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_bid_price,
            { DERIBIT_ORDERSAPI_BID_PRICE_NAME,
              DERIBIT_ORDERSAPI_BID_PRICE_FILTER,
              DERIBIT_ORDERSAPI_BID_PRICE_TYPE,
              DERIBIT_ORDERSAPI_BID_PRICE_DISPLAY,
              CF_FUNC(deribit_ordersapi_format_decimal_9_64),
              DERIBIT_ORDERSAPI_BID_PRICE_MASK,
              DERIBIT_ORDERSAPI_BID_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_bid_price_optional,
            { DERIBIT_ORDERSAPI_BID_PRICE_OPTIONAL_NAME,
              DERIBIT_ORDERSAPI_BID_PRICE_OPTIONAL_FILTER,
              DERIBIT_ORDERSAPI_BID_PRICE_OPTIONAL_TYPE,
              DERIBIT_ORDERSAPI_BID_PRICE_OPTIONAL_DISPLAY,
              CF_FUNC(deribit_ordersapi_format_decimal_9_64_nullable),
              DERIBIT_ORDERSAPI_BID_PRICE_OPTIONAL_MASK,
              DERIBIT_ORDERSAPI_BID_PRICE_OPTIONAL_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_bid_reject_reason,
            { DERIBIT_ORDERSAPI_BID_REJECT_REASON_NAME,
              DERIBIT_ORDERSAPI_BID_REJECT_REASON_FILTER,
              DERIBIT_ORDERSAPI_BID_REJECT_REASON_TYPE,
              DERIBIT_ORDERSAPI_BID_REJECT_REASON_DISPLAY,
              VALS(deribit_ordersapi_bid_reject_reason_vals),
              DERIBIT_ORDERSAPI_BID_REJECT_REASON_MASK,
              DERIBIT_ORDERSAPI_BID_REJECT_REASON_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_bid_status,
            { DERIBIT_ORDERSAPI_BID_STATUS_NAME,
              DERIBIT_ORDERSAPI_BID_STATUS_FILTER,
              DERIBIT_ORDERSAPI_BID_STATUS_TYPE,
              DERIBIT_ORDERSAPI_BID_STATUS_DISPLAY,
              VALS(deribit_ordersapi_bid_status_vals),
              DERIBIT_ORDERSAPI_BID_STATUS_MASK,
              DERIBIT_ORDERSAPI_BID_STATUS_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_block_length,
            { DERIBIT_ORDERSAPI_BLOCK_LENGTH_NAME,
              DERIBIT_ORDERSAPI_BLOCK_LENGTH_FILTER,
              DERIBIT_ORDERSAPI_BLOCK_LENGTH_TYPE,
              DERIBIT_ORDERSAPI_BLOCK_LENGTH_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_BLOCK_LENGTH_MASK,
              DERIBIT_ORDERSAPI_BLOCK_LENGTH_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_cancel_reason,
            { DERIBIT_ORDERSAPI_CANCEL_REASON_NAME,
              DERIBIT_ORDERSAPI_CANCEL_REASON_FILTER,
              DERIBIT_ORDERSAPI_CANCEL_REASON_TYPE,
              DERIBIT_ORDERSAPI_CANCEL_REASON_DISPLAY,
              VALS(deribit_ordersapi_cancel_reason_vals),
              DERIBIT_ORDERSAPI_CANCEL_REASON_MASK,
              DERIBIT_ORDERSAPI_CANCEL_REASON_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_client_id,
            { DERIBIT_ORDERSAPI_CLIENT_ID_NAME,
              DERIBIT_ORDERSAPI_CLIENT_ID_FILTER,
              DERIBIT_ORDERSAPI_CLIENT_ID_TYPE,
              DERIBIT_ORDERSAPI_CLIENT_ID_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_CLIENT_ID_MASK,
              DERIBIT_ORDERSAPI_CLIENT_ID_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_client_order_id,
            { DERIBIT_ORDERSAPI_CLIENT_ORDER_ID_NAME,
              DERIBIT_ORDERSAPI_CLIENT_ORDER_ID_FILTER,
              DERIBIT_ORDERSAPI_CLIENT_ORDER_ID_TYPE,
              DERIBIT_ORDERSAPI_CLIENT_ORDER_ID_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_CLIENT_ORDER_ID_MASK,
              DERIBIT_ORDERSAPI_CLIENT_ORDER_ID_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_correlation_id,
            { DERIBIT_ORDERSAPI_CORRELATION_ID_NAME,
              DERIBIT_ORDERSAPI_CORRELATION_ID_FILTER,
              DERIBIT_ORDERSAPI_CORRELATION_ID_TYPE,
              DERIBIT_ORDERSAPI_CORRELATION_ID_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_CORRELATION_ID_MASK,
              DERIBIT_ORDERSAPI_CORRELATION_ID_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_correlation_id_optional,
            { DERIBIT_ORDERSAPI_CORRELATION_ID_OPTIONAL_NAME,
              DERIBIT_ORDERSAPI_CORRELATION_ID_OPTIONAL_FILTER,
              DERIBIT_ORDERSAPI_CORRELATION_ID_OPTIONAL_TYPE,
              DERIBIT_ORDERSAPI_CORRELATION_ID_OPTIONAL_DISPLAY,
              CF_FUNC(deribit_ordersapi_format_nullable_64),
              DERIBIT_ORDERSAPI_CORRELATION_ID_OPTIONAL_MASK,
              DERIBIT_ORDERSAPI_CORRELATION_ID_OPTIONAL_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_currency_pair_id,
            { DERIBIT_ORDERSAPI_CURRENCY_PAIR_ID_NAME,
              DERIBIT_ORDERSAPI_CURRENCY_PAIR_ID_FILTER,
              DERIBIT_ORDERSAPI_CURRENCY_PAIR_ID_TYPE,
              DERIBIT_ORDERSAPI_CURRENCY_PAIR_ID_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_CURRENCY_PAIR_ID_MASK,
              DERIBIT_ORDERSAPI_CURRENCY_PAIR_ID_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_delta_level,
            { DERIBIT_ORDERSAPI_DELTA_LEVEL_NAME,
              DERIBIT_ORDERSAPI_DELTA_LEVEL_FILTER,
              DERIBIT_ORDERSAPI_DELTA_LEVEL_TYPE,
              DERIBIT_ORDERSAPI_DELTA_LEVEL_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_DELTA_LEVEL_MASK,
              DERIBIT_ORDERSAPI_DELTA_LEVEL_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_details_data,
            { DERIBIT_ORDERSAPI_DETAILS_DATA_NAME,
              DERIBIT_ORDERSAPI_DETAILS_DATA_FILTER,
              DERIBIT_ORDERSAPI_DETAILS_DATA_TYPE,
              DERIBIT_ORDERSAPI_DETAILS_DATA_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_DETAILS_DATA_MASK,
              NULL,
              HFILL } },
        { &hf_deribit_ordersapi_details_length,
            { DERIBIT_ORDERSAPI_DETAILS_LENGTH_NAME,
              DERIBIT_ORDERSAPI_DETAILS_LENGTH_FILTER,
              DERIBIT_ORDERSAPI_DETAILS_LENGTH_TYPE,
              DERIBIT_ORDERSAPI_DETAILS_LENGTH_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_DETAILS_LENGTH_MASK,
              NULL,
              HFILL } },
        { &hf_deribit_ordersapi_exec_id,
            { DERIBIT_ORDERSAPI_EXEC_ID_NAME,
              DERIBIT_ORDERSAPI_EXEC_ID_FILTER,
              DERIBIT_ORDERSAPI_EXEC_ID_TYPE,
              DERIBIT_ORDERSAPI_EXEC_ID_DISPLAY,
              CF_FUNC(deribit_ordersapi_format_nullable_64),
              DERIBIT_ORDERSAPI_EXEC_ID_MASK,
              DERIBIT_ORDERSAPI_EXEC_ID_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_exponent,
            { DERIBIT_ORDERSAPI_EXPONENT_NAME,
              DERIBIT_ORDERSAPI_EXPONENT_FILTER,
              DERIBIT_ORDERSAPI_EXPONENT_TYPE,
              DERIBIT_ORDERSAPI_EXPONENT_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_EXPONENT_MASK,
              NULL,
              HFILL } },
        { &hf_deribit_ordersapi_fill_id,
            { DERIBIT_ORDERSAPI_FILL_ID_NAME,
              DERIBIT_ORDERSAPI_FILL_ID_FILTER,
              DERIBIT_ORDERSAPI_FILL_ID_TYPE,
              DERIBIT_ORDERSAPI_FILL_ID_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_FILL_ID_MASK,
              DERIBIT_ORDERSAPI_FILL_ID_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_fill_price,
            { DERIBIT_ORDERSAPI_FILL_PRICE_NAME,
              DERIBIT_ORDERSAPI_FILL_PRICE_FILTER,
              DERIBIT_ORDERSAPI_FILL_PRICE_TYPE,
              DERIBIT_ORDERSAPI_FILL_PRICE_DISPLAY,
              CF_FUNC(deribit_ordersapi_format_decimal_9_64),
              DERIBIT_ORDERSAPI_FILL_PRICE_MASK,
              DERIBIT_ORDERSAPI_FILL_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_from_sequence_number,
            { DERIBIT_ORDERSAPI_FROM_SEQUENCE_NUMBER_NAME,
              DERIBIT_ORDERSAPI_FROM_SEQUENCE_NUMBER_FILTER,
              DERIBIT_ORDERSAPI_FROM_SEQUENCE_NUMBER_TYPE,
              DERIBIT_ORDERSAPI_FROM_SEQUENCE_NUMBER_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_FROM_SEQUENCE_NUMBER_MASK,
              DERIBIT_ORDERSAPI_FROM_SEQUENCE_NUMBER_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_frozen_until,
            { DERIBIT_ORDERSAPI_FROZEN_UNTIL_NAME,
              DERIBIT_ORDERSAPI_FROZEN_UNTIL_FILTER,
              DERIBIT_ORDERSAPI_FROZEN_UNTIL_TYPE,
              DERIBIT_ORDERSAPI_FROZEN_UNTIL_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_FROZEN_UNTIL_MASK,
              DERIBIT_ORDERSAPI_FROZEN_UNTIL_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_frozen_until_time,
            { DERIBIT_ORDERSAPI_FROZEN_UNTIL_TIME_NAME,
              DERIBIT_ORDERSAPI_FROZEN_UNTIL_TIME_FILTER,
              DERIBIT_ORDERSAPI_FROZEN_UNTIL_TIME_TYPE,
              DERIBIT_ORDERSAPI_FROZEN_UNTIL_TIME_DISPLAY,
              CF_FUNC(deribit_ordersapi_format_nullable_64),
              DERIBIT_ORDERSAPI_FROZEN_UNTIL_TIME_MASK,
              DERIBIT_ORDERSAPI_FROZEN_UNTIL_TIME_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_heartbeat_interval_seconds,
            { DERIBIT_ORDERSAPI_HEARTBEAT_INTERVAL_SECONDS_NAME,
              DERIBIT_ORDERSAPI_HEARTBEAT_INTERVAL_SECONDS_FILTER,
              DERIBIT_ORDERSAPI_HEARTBEAT_INTERVAL_SECONDS_TYPE,
              DERIBIT_ORDERSAPI_HEARTBEAT_INTERVAL_SECONDS_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_HEARTBEAT_INTERVAL_SECONDS_MASK,
              DERIBIT_ORDERSAPI_HEARTBEAT_INTERVAL_SECONDS_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_instrument_id,
            { DERIBIT_ORDERSAPI_INSTRUMENT_ID_NAME,
              DERIBIT_ORDERSAPI_INSTRUMENT_ID_FILTER,
              DERIBIT_ORDERSAPI_INSTRUMENT_ID_TYPE,
              DERIBIT_ORDERSAPI_INSTRUMENT_ID_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_INSTRUMENT_ID_MASK,
              DERIBIT_ORDERSAPI_INSTRUMENT_ID_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_instrument_id_optional,
            { DERIBIT_ORDERSAPI_INSTRUMENT_ID_OPTIONAL_NAME,
              DERIBIT_ORDERSAPI_INSTRUMENT_ID_OPTIONAL_FILTER,
              DERIBIT_ORDERSAPI_INSTRUMENT_ID_OPTIONAL_TYPE,
              DERIBIT_ORDERSAPI_INSTRUMENT_ID_OPTIONAL_DISPLAY,
              CF_FUNC(deribit_ordersapi_format_nullable_64),
              DERIBIT_ORDERSAPI_INSTRUMENT_ID_OPTIONAL_MASK,
              DERIBIT_ORDERSAPI_INSTRUMENT_ID_OPTIONAL_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_last_processed_seq_no,
            { DERIBIT_ORDERSAPI_LAST_PROCESSED_SEQ_NO_NAME,
              DERIBIT_ORDERSAPI_LAST_PROCESSED_SEQ_NO_FILTER,
              DERIBIT_ORDERSAPI_LAST_PROCESSED_SEQ_NO_TYPE,
              DERIBIT_ORDERSAPI_LAST_PROCESSED_SEQ_NO_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_LAST_PROCESSED_SEQ_NO_MASK,
              DERIBIT_ORDERSAPI_LAST_PROCESSED_SEQ_NO_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_leg_side,
            { DERIBIT_ORDERSAPI_LEG_SIDE_NAME,
              DERIBIT_ORDERSAPI_LEG_SIDE_FILTER,
              DERIBIT_ORDERSAPI_LEG_SIDE_TYPE,
              DERIBIT_ORDERSAPI_LEG_SIDE_DISPLAY,
              VALS(deribit_ordersapi_leg_side_vals),
              DERIBIT_ORDERSAPI_LEG_SIDE_MASK,
              DERIBIT_ORDERSAPI_LEG_SIDE_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_mantissa,
            { DERIBIT_ORDERSAPI_MANTISSA_NAME,
              DERIBIT_ORDERSAPI_MANTISSA_FILTER,
              DERIBIT_ORDERSAPI_MANTISSA_TYPE,
              DERIBIT_ORDERSAPI_MANTISSA_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_MANTISSA_MASK,
              NULL,
              HFILL } },
        { &hf_deribit_ordersapi_match_id,
            { DERIBIT_ORDERSAPI_MATCH_ID_NAME,
              DERIBIT_ORDERSAPI_MATCH_ID_FILTER,
              DERIBIT_ORDERSAPI_MATCH_ID_TYPE,
              DERIBIT_ORDERSAPI_MATCH_ID_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_MATCH_ID_MASK,
              DERIBIT_ORDERSAPI_MATCH_ID_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_message_length,
            { DERIBIT_ORDERSAPI_MESSAGE_LENGTH_NAME,
              DERIBIT_ORDERSAPI_MESSAGE_LENGTH_FILTER,
              DERIBIT_ORDERSAPI_MESSAGE_LENGTH_TYPE,
              DERIBIT_ORDERSAPI_MESSAGE_LENGTH_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_MESSAGE_LENGTH_MASK,
              DERIBIT_ORDERSAPI_MESSAGE_LENGTH_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_mmp_group_id,
            { DERIBIT_ORDERSAPI_MMP_GROUP_ID_NAME,
              DERIBIT_ORDERSAPI_MMP_GROUP_ID_FILTER,
              DERIBIT_ORDERSAPI_MMP_GROUP_ID_TYPE,
              DERIBIT_ORDERSAPI_MMP_GROUP_ID_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_MMP_GROUP_ID_MASK,
              DERIBIT_ORDERSAPI_MMP_GROUP_ID_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_new_sequence_number,
            { DERIBIT_ORDERSAPI_NEW_SEQUENCE_NUMBER_NAME,
              DERIBIT_ORDERSAPI_NEW_SEQUENCE_NUMBER_FILTER,
              DERIBIT_ORDERSAPI_NEW_SEQUENCE_NUMBER_TYPE,
              DERIBIT_ORDERSAPI_NEW_SEQUENCE_NUMBER_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_NEW_SEQUENCE_NUMBER_MASK,
              DERIBIT_ORDERSAPI_NEW_SEQUENCE_NUMBER_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_num_in_group,
            { DERIBIT_ORDERSAPI_NUM_IN_GROUP_NAME,
              DERIBIT_ORDERSAPI_NUM_IN_GROUP_FILTER,
              DERIBIT_ORDERSAPI_NUM_IN_GROUP_TYPE,
              DERIBIT_ORDERSAPI_NUM_IN_GROUP_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_NUM_IN_GROUP_MASK,
              DERIBIT_ORDERSAPI_NUM_IN_GROUP_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_order_id,
            { DERIBIT_ORDERSAPI_ORDER_ID_NAME,
              DERIBIT_ORDERSAPI_ORDER_ID_FILTER,
              DERIBIT_ORDERSAPI_ORDER_ID_TYPE,
              DERIBIT_ORDERSAPI_ORDER_ID_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_ORDER_ID_MASK,
              DERIBIT_ORDERSAPI_ORDER_ID_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_order_id_fill_id,
            { DERIBIT_ORDERSAPI_ORDER_ID_FILL_ID_NAME,
              DERIBIT_ORDERSAPI_ORDER_ID_FILL_ID_FILTER,
              DERIBIT_ORDERSAPI_ORDER_ID_FILL_ID_TYPE,
              DERIBIT_ORDERSAPI_ORDER_ID_FILL_ID_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_ORDER_ID_FILL_ID_MASK,
              DERIBIT_ORDERSAPI_ORDER_ID_FILL_ID_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_order_id_optional,
            { DERIBIT_ORDERSAPI_ORDER_ID_OPTIONAL_NAME,
              DERIBIT_ORDERSAPI_ORDER_ID_OPTIONAL_FILTER,
              DERIBIT_ORDERSAPI_ORDER_ID_OPTIONAL_TYPE,
              DERIBIT_ORDERSAPI_ORDER_ID_OPTIONAL_DISPLAY,
              CF_FUNC(deribit_ordersapi_format_nullable_64),
              DERIBIT_ORDERSAPI_ORDER_ID_OPTIONAL_MASK,
              DERIBIT_ORDERSAPI_ORDER_ID_OPTIONAL_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_padding,
            { DERIBIT_ORDERSAPI_PADDING_NAME,
              DERIBIT_ORDERSAPI_PADDING_FILTER,
              DERIBIT_ORDERSAPI_PADDING_TYPE,
              DERIBIT_ORDERSAPI_PADDING_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_PADDING_MASK,
              DERIBIT_ORDERSAPI_PADDING_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_padding_3,
            { DERIBIT_ORDERSAPI_PADDING_3_NAME,
              DERIBIT_ORDERSAPI_PADDING_3_FILTER,
              DERIBIT_ORDERSAPI_PADDING_3_TYPE,
              DERIBIT_ORDERSAPI_PADDING_3_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_PADDING_3_MASK,
              DERIBIT_ORDERSAPI_PADDING_3_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_price,
            { DERIBIT_ORDERSAPI_PRICE_NAME,
              DERIBIT_ORDERSAPI_PRICE_FILTER,
              DERIBIT_ORDERSAPI_PRICE_TYPE,
              DERIBIT_ORDERSAPI_PRICE_DISPLAY,
              CF_FUNC(deribit_ordersapi_format_decimal_9_64),
              DERIBIT_ORDERSAPI_PRICE_MASK,
              NULL,
              HFILL } },
        { &hf_deribit_ordersapi_product_type,
            { DERIBIT_ORDERSAPI_PRODUCT_TYPE_NAME,
              DERIBIT_ORDERSAPI_PRODUCT_TYPE_FILTER,
              DERIBIT_ORDERSAPI_PRODUCT_TYPE_TYPE,
              DERIBIT_ORDERSAPI_PRODUCT_TYPE_DISPLAY,
              VALS(deribit_ordersapi_product_type_vals),
              DERIBIT_ORDERSAPI_PRODUCT_TYPE_MASK,
              DERIBIT_ORDERSAPI_PRODUCT_TYPE_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_protocol_id,
            { DERIBIT_ORDERSAPI_PROTOCOL_ID_NAME,
              DERIBIT_ORDERSAPI_PROTOCOL_ID_FILTER,
              DERIBIT_ORDERSAPI_PROTOCOL_ID_TYPE,
              DERIBIT_ORDERSAPI_PROTOCOL_ID_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_PROTOCOL_ID_MASK,
              DERIBIT_ORDERSAPI_PROTOCOL_ID_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_quantity_level,
            { DERIBIT_ORDERSAPI_QUANTITY_LEVEL_NAME,
              DERIBIT_ORDERSAPI_QUANTITY_LEVEL_FILTER,
              DERIBIT_ORDERSAPI_QUANTITY_LEVEL_TYPE,
              DERIBIT_ORDERSAPI_QUANTITY_LEVEL_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_QUANTITY_LEVEL_MASK,
              DERIBIT_ORDERSAPI_QUANTITY_LEVEL_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_quote_id,
            { DERIBIT_ORDERSAPI_QUOTE_ID_NAME,
              DERIBIT_ORDERSAPI_QUOTE_ID_FILTER,
              DERIBIT_ORDERSAPI_QUOTE_ID_TYPE,
              DERIBIT_ORDERSAPI_QUOTE_ID_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_QUOTE_ID_MASK,
              DERIBIT_ORDERSAPI_QUOTE_ID_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_reason_cancel_order_reject_reason,
            { DERIBIT_ORDERSAPI_REASON_CANCEL_ORDER_REJECT_REASON_NAME,
              DERIBIT_ORDERSAPI_REASON_CANCEL_ORDER_REJECT_REASON_FILTER,
              DERIBIT_ORDERSAPI_REASON_CANCEL_ORDER_REJECT_REASON_TYPE,
              DERIBIT_ORDERSAPI_REASON_CANCEL_ORDER_REJECT_REASON_DISPLAY,
              VALS(deribit_ordersapi_reason_cancel_order_reject_reason_vals),
              DERIBIT_ORDERSAPI_REASON_CANCEL_ORDER_REJECT_REASON_MASK,
              DERIBIT_ORDERSAPI_REASON_CANCEL_ORDER_REJECT_REASON_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_reason_data,
            { DERIBIT_ORDERSAPI_REASON_DATA_NAME,
              DERIBIT_ORDERSAPI_REASON_DATA_FILTER,
              DERIBIT_ORDERSAPI_REASON_DATA_TYPE,
              DERIBIT_ORDERSAPI_REASON_DATA_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_REASON_DATA_MASK,
              NULL,
              HFILL } },
        { &hf_deribit_ordersapi_reason_length,
            { DERIBIT_ORDERSAPI_REASON_LENGTH_NAME,
              DERIBIT_ORDERSAPI_REASON_LENGTH_FILTER,
              DERIBIT_ORDERSAPI_REASON_LENGTH_TYPE,
              DERIBIT_ORDERSAPI_REASON_LENGTH_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_REASON_LENGTH_MASK,
              NULL,
              HFILL } },
        { &hf_deribit_ordersapi_reason_mass_cancel_reject_reason,
            { DERIBIT_ORDERSAPI_REASON_MASS_CANCEL_REJECT_REASON_NAME,
              DERIBIT_ORDERSAPI_REASON_MASS_CANCEL_REJECT_REASON_FILTER,
              DERIBIT_ORDERSAPI_REASON_MASS_CANCEL_REJECT_REASON_TYPE,
              DERIBIT_ORDERSAPI_REASON_MASS_CANCEL_REJECT_REASON_DISPLAY,
              VALS(deribit_ordersapi_reason_mass_cancel_reject_reason_vals),
              DERIBIT_ORDERSAPI_REASON_MASS_CANCEL_REJECT_REASON_MASK,
              DERIBIT_ORDERSAPI_REASON_MASS_CANCEL_REJECT_REASON_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_reason_mass_quote_reject_reason,
            { DERIBIT_ORDERSAPI_REASON_MASS_QUOTE_REJECT_REASON_NAME,
              DERIBIT_ORDERSAPI_REASON_MASS_QUOTE_REJECT_REASON_FILTER,
              DERIBIT_ORDERSAPI_REASON_MASS_QUOTE_REJECT_REASON_TYPE,
              DERIBIT_ORDERSAPI_REASON_MASS_QUOTE_REJECT_REASON_DISPLAY,
              VALS(deribit_ordersapi_reason_mass_quote_reject_reason_vals),
              DERIBIT_ORDERSAPI_REASON_MASS_QUOTE_REJECT_REASON_MASK,
              DERIBIT_ORDERSAPI_REASON_MASS_QUOTE_REJECT_REASON_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_reason_mmp_status_reject_reason,
            { DERIBIT_ORDERSAPI_REASON_MMP_STATUS_REJECT_REASON_NAME,
              DERIBIT_ORDERSAPI_REASON_MMP_STATUS_REJECT_REASON_FILTER,
              DERIBIT_ORDERSAPI_REASON_MMP_STATUS_REJECT_REASON_TYPE,
              DERIBIT_ORDERSAPI_REASON_MMP_STATUS_REJECT_REASON_DISPLAY,
              VALS(deribit_ordersapi_reason_mmp_status_reject_reason_vals),
              DERIBIT_ORDERSAPI_REASON_MMP_STATUS_REJECT_REASON_MASK,
              DERIBIT_ORDERSAPI_REASON_MMP_STATUS_REJECT_REASON_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_reason_order_reject_reason,
            { DERIBIT_ORDERSAPI_REASON_ORDER_REJECT_REASON_NAME,
              DERIBIT_ORDERSAPI_REASON_ORDER_REJECT_REASON_FILTER,
              DERIBIT_ORDERSAPI_REASON_ORDER_REJECT_REASON_TYPE,
              DERIBIT_ORDERSAPI_REASON_ORDER_REJECT_REASON_DISPLAY,
              VALS(deribit_ordersapi_reason_order_reject_reason_vals),
              DERIBIT_ORDERSAPI_REASON_ORDER_REJECT_REASON_MASK,
              DERIBIT_ORDERSAPI_REASON_ORDER_REJECT_REASON_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_reason_reject_reason,
            { DERIBIT_ORDERSAPI_REASON_REJECT_REASON_NAME,
              DERIBIT_ORDERSAPI_REASON_REJECT_REASON_FILTER,
              DERIBIT_ORDERSAPI_REASON_REJECT_REASON_TYPE,
              DERIBIT_ORDERSAPI_REASON_REJECT_REASON_DISPLAY,
              VALS(deribit_ordersapi_reason_reject_reason_vals),
              DERIBIT_ORDERSAPI_REASON_REJECT_REASON_MASK,
              DERIBIT_ORDERSAPI_REASON_REJECT_REASON_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_receive_time,
            { DERIBIT_ORDERSAPI_RECEIVE_TIME_NAME,
              DERIBIT_ORDERSAPI_RECEIVE_TIME_FILTER,
              DERIBIT_ORDERSAPI_RECEIVE_TIME_TYPE,
              DERIBIT_ORDERSAPI_RECEIVE_TIME_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_RECEIVE_TIME_MASK,
              DERIBIT_ORDERSAPI_RECEIVE_TIME_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_ref_sequence_number,
            { DERIBIT_ORDERSAPI_REF_SEQUENCE_NUMBER_NAME,
              DERIBIT_ORDERSAPI_REF_SEQUENCE_NUMBER_FILTER,
              DERIBIT_ORDERSAPI_REF_SEQUENCE_NUMBER_TYPE,
              DERIBIT_ORDERSAPI_REF_SEQUENCE_NUMBER_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_REF_SEQUENCE_NUMBER_MASK,
              DERIBIT_ORDERSAPI_REF_SEQUENCE_NUMBER_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_reset_seq_num,
            { DERIBIT_ORDERSAPI_RESET_SEQ_NUM_NAME,
              DERIBIT_ORDERSAPI_RESET_SEQ_NUM_FILTER,
              DERIBIT_ORDERSAPI_RESET_SEQ_NUM_TYPE,
              DERIBIT_ORDERSAPI_RESET_SEQ_NUM_DISPLAY,
              VALS(deribit_ordersapi_reset_seq_num_vals),
              DERIBIT_ORDERSAPI_RESET_SEQ_NUM_MASK,
              DERIBIT_ORDERSAPI_RESET_SEQ_NUM_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_schema_version,
            { DERIBIT_ORDERSAPI_SCHEMA_VERSION_NAME,
              DERIBIT_ORDERSAPI_SCHEMA_VERSION_FILTER,
              DERIBIT_ORDERSAPI_SCHEMA_VERSION_TYPE,
              DERIBIT_ORDERSAPI_SCHEMA_VERSION_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_SCHEMA_VERSION_MASK,
              DERIBIT_ORDERSAPI_SCHEMA_VERSION_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_secret,
            { DERIBIT_ORDERSAPI_SECRET_NAME,
              DERIBIT_ORDERSAPI_SECRET_FILTER,
              DERIBIT_ORDERSAPI_SECRET_TYPE,
              DERIBIT_ORDERSAPI_SECRET_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_SECRET_MASK,
              NULL,
              HFILL } },
        { &hf_deribit_ordersapi_self_match_prevention_id,
            { DERIBIT_ORDERSAPI_SELF_MATCH_PREVENTION_ID_NAME,
              DERIBIT_ORDERSAPI_SELF_MATCH_PREVENTION_ID_FILTER,
              DERIBIT_ORDERSAPI_SELF_MATCH_PREVENTION_ID_TYPE,
              DERIBIT_ORDERSAPI_SELF_MATCH_PREVENTION_ID_DISPLAY,
              CF_FUNC(deribit_ordersapi_format_nullable_64),
              DERIBIT_ORDERSAPI_SELF_MATCH_PREVENTION_ID_MASK,
              DERIBIT_ORDERSAPI_SELF_MATCH_PREVENTION_ID_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_self_trading_mode,
            { DERIBIT_ORDERSAPI_SELF_TRADING_MODE_NAME,
              DERIBIT_ORDERSAPI_SELF_TRADING_MODE_FILTER,
              DERIBIT_ORDERSAPI_SELF_TRADING_MODE_TYPE,
              DERIBIT_ORDERSAPI_SELF_TRADING_MODE_DISPLAY,
              VALS(deribit_ordersapi_self_trading_mode_vals),
              DERIBIT_ORDERSAPI_SELF_TRADING_MODE_MASK,
              DERIBIT_ORDERSAPI_SELF_TRADING_MODE_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_send_time_ns,
            { DERIBIT_ORDERSAPI_SEND_TIME_NS_NAME,
              DERIBIT_ORDERSAPI_SEND_TIME_NS_FILTER,
              DERIBIT_ORDERSAPI_SEND_TIME_NS_TYPE,
              DERIBIT_ORDERSAPI_SEND_TIME_NS_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_SEND_TIME_NS_MASK,
              DERIBIT_ORDERSAPI_SEND_TIME_NS_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_sequence_number,
            { DERIBIT_ORDERSAPI_SEQUENCE_NUMBER_NAME,
              DERIBIT_ORDERSAPI_SEQUENCE_NUMBER_FILTER,
              DERIBIT_ORDERSAPI_SEQUENCE_NUMBER_TYPE,
              DERIBIT_ORDERSAPI_SEQUENCE_NUMBER_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_SEQUENCE_NUMBER_MASK,
              DERIBIT_ORDERSAPI_SEQUENCE_NUMBER_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_session_cancel_on_disconnect,
            { DERIBIT_ORDERSAPI_SESSION_CANCEL_ON_DISCONNECT_NAME,
              DERIBIT_ORDERSAPI_SESSION_CANCEL_ON_DISCONNECT_FILTER,
              DERIBIT_ORDERSAPI_SESSION_CANCEL_ON_DISCONNECT_TYPE,
              DERIBIT_ORDERSAPI_SESSION_CANCEL_ON_DISCONNECT_DISPLAY,
              VALS(deribit_ordersapi_session_cancel_on_disconnect_vals),
              DERIBIT_ORDERSAPI_SESSION_CANCEL_ON_DISCONNECT_MASK,
              DERIBIT_ORDERSAPI_SESSION_CANCEL_ON_DISCONNECT_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_side,
            { DERIBIT_ORDERSAPI_SIDE_NAME,
              DERIBIT_ORDERSAPI_SIDE_FILTER,
              DERIBIT_ORDERSAPI_SIDE_TYPE,
              DERIBIT_ORDERSAPI_SIDE_DISPLAY,
              VALS(deribit_ordersapi_side_vals),
              DERIBIT_ORDERSAPI_SIDE_MASK,
              NULL,
              HFILL } },
        { &hf_deribit_ordersapi_status,
            { DERIBIT_ORDERSAPI_STATUS_NAME,
              DERIBIT_ORDERSAPI_STATUS_FILTER,
              DERIBIT_ORDERSAPI_STATUS_TYPE,
              DERIBIT_ORDERSAPI_STATUS_DISPLAY,
              VALS(deribit_ordersapi_status_vals),
              DERIBIT_ORDERSAPI_STATUS_MASK,
              NULL,
              HFILL } },
        { &hf_deribit_ordersapi_template_id,
            { DERIBIT_ORDERSAPI_TEMPLATE_ID_NAME,
              DERIBIT_ORDERSAPI_TEMPLATE_ID_FILTER,
              DERIBIT_ORDERSAPI_TEMPLATE_ID_TYPE,
              DERIBIT_ORDERSAPI_TEMPLATE_ID_DISPLAY,
              VALS(deribit_ordersapi_template_id_vals),
              DERIBIT_ORDERSAPI_TEMPLATE_ID_MASK,
              DERIBIT_ORDERSAPI_TEMPLATE_ID_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_time_in_force,
            { DERIBIT_ORDERSAPI_TIME_IN_FORCE_NAME,
              DERIBIT_ORDERSAPI_TIME_IN_FORCE_FILTER,
              DERIBIT_ORDERSAPI_TIME_IN_FORCE_TYPE,
              DERIBIT_ORDERSAPI_TIME_IN_FORCE_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_TIME_IN_FORCE_MASK,
              DERIBIT_ORDERSAPI_TIME_IN_FORCE_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_timestamp,
            { DERIBIT_ORDERSAPI_TIMESTAMP_NAME,
              DERIBIT_ORDERSAPI_TIMESTAMP_FILTER,
              DERIBIT_ORDERSAPI_TIMESTAMP_TYPE,
              DERIBIT_ORDERSAPI_TIMESTAMP_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_TIMESTAMP_MASK,
              NULL,
              HFILL } },
        { &hf_deribit_ordersapi_to_sequence_number,
            { DERIBIT_ORDERSAPI_TO_SEQUENCE_NUMBER_NAME,
              DERIBIT_ORDERSAPI_TO_SEQUENCE_NUMBER_FILTER,
              DERIBIT_ORDERSAPI_TO_SEQUENCE_NUMBER_TYPE,
              DERIBIT_ORDERSAPI_TO_SEQUENCE_NUMBER_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_TO_SEQUENCE_NUMBER_MASK,
              DERIBIT_ORDERSAPI_TO_SEQUENCE_NUMBER_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_total_order_count,
            { DERIBIT_ORDERSAPI_TOTAL_ORDER_COUNT_NAME,
              DERIBIT_ORDERSAPI_TOTAL_ORDER_COUNT_FILTER,
              DERIBIT_ORDERSAPI_TOTAL_ORDER_COUNT_TYPE,
              DERIBIT_ORDERSAPI_TOTAL_ORDER_COUNT_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_TOTAL_ORDER_COUNT_MASK,
              DERIBIT_ORDERSAPI_TOTAL_ORDER_COUNT_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_trigger,
            { DERIBIT_ORDERSAPI_TRIGGER_NAME,
              DERIBIT_ORDERSAPI_TRIGGER_FILTER,
              DERIBIT_ORDERSAPI_TRIGGER_TYPE,
              DERIBIT_ORDERSAPI_TRIGGER_DISPLAY,
              VALS(deribit_ordersapi_trigger_vals),
              DERIBIT_ORDERSAPI_TRIGGER_MASK,
              NULL,
              HFILL } },
        { &hf_deribit_ordersapi_vega_level,
            { DERIBIT_ORDERSAPI_VEGA_LEVEL_NAME,
              DERIBIT_ORDERSAPI_VEGA_LEVEL_FILTER,
              DERIBIT_ORDERSAPI_VEGA_LEVEL_TYPE,
              DERIBIT_ORDERSAPI_VEGA_LEVEL_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_VEGA_LEVEL_MASK,
              DERIBIT_ORDERSAPI_VEGA_LEVEL_DESCRIPTION,
              HFILL } },

        /* Bit Fields */
        { &hf_deribit_ordersapi_cancel_on_disconnect,
            { DERIBIT_ORDERSAPI_CANCEL_ON_DISCONNECT_NAME,
              DERIBIT_ORDERSAPI_CANCEL_ON_DISCONNECT_FILTER,
              DERIBIT_ORDERSAPI_CANCEL_ON_DISCONNECT_TYPE,
              DERIBIT_ORDERSAPI_CANCEL_ON_DISCONNECT_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_CANCEL_ON_DISCONNECT_MASK,
              DERIBIT_ORDERSAPI_CANCEL_ON_DISCONNECT_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_is_fully_filled,
            { DERIBIT_ORDERSAPI_IS_FULLY_FILLED_NAME,
              DERIBIT_ORDERSAPI_IS_FULLY_FILLED_FILTER,
              DERIBIT_ORDERSAPI_IS_FULLY_FILLED_TYPE,
              DERIBIT_ORDERSAPI_IS_FULLY_FILLED_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_IS_FULLY_FILLED_MASK,
              DERIBIT_ORDERSAPI_IS_FULLY_FILLED_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_is_last_message,
            { DERIBIT_ORDERSAPI_IS_LAST_MESSAGE_NAME,
              DERIBIT_ORDERSAPI_IS_LAST_MESSAGE_FILTER,
              DERIBIT_ORDERSAPI_IS_LAST_MESSAGE_TYPE,
              DERIBIT_ORDERSAPI_IS_LAST_MESSAGE_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_IS_LAST_MESSAGE_MASK,
              DERIBIT_ORDERSAPI_IS_LAST_MESSAGE_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_is_quote,
            { DERIBIT_ORDERSAPI_IS_QUOTE_NAME,
              DERIBIT_ORDERSAPI_IS_QUOTE_FILTER,
              DERIBIT_ORDERSAPI_IS_QUOTE_TYPE,
              DERIBIT_ORDERSAPI_IS_QUOTE_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_IS_QUOTE_MASK,
              DERIBIT_ORDERSAPI_IS_QUOTE_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_is_resend,
            { DERIBIT_ORDERSAPI_IS_RESEND_NAME,
              DERIBIT_ORDERSAPI_IS_RESEND_FILTER,
              DERIBIT_ORDERSAPI_IS_RESEND_TYPE,
              DERIBIT_ORDERSAPI_IS_RESEND_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_IS_RESEND_MASK,
              DERIBIT_ORDERSAPI_IS_RESEND_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_market_limit,
            { DERIBIT_ORDERSAPI_MARKET_LIMIT_NAME,
              DERIBIT_ORDERSAPI_MARKET_LIMIT_FILTER,
              DERIBIT_ORDERSAPI_MARKET_LIMIT_TYPE,
              DERIBIT_ORDERSAPI_MARKET_LIMIT_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_MARKET_LIMIT_MASK,
              DERIBIT_ORDERSAPI_MARKET_LIMIT_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_mmp,
            { DERIBIT_ORDERSAPI_MMP_NAME,
              DERIBIT_ORDERSAPI_MMP_FILTER,
              DERIBIT_ORDERSAPI_MMP_TYPE,
              DERIBIT_ORDERSAPI_MMP_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_MMP_MASK,
              NULL,
              HFILL } },
        { &hf_deribit_ordersapi_post_only,
            { DERIBIT_ORDERSAPI_POST_ONLY_NAME,
              DERIBIT_ORDERSAPI_POST_ONLY_FILTER,
              DERIBIT_ORDERSAPI_POST_ONLY_TYPE,
              DERIBIT_ORDERSAPI_POST_ONLY_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_POST_ONLY_MASK,
              DERIBIT_ORDERSAPI_POST_ONLY_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_post_only_reject,
            { DERIBIT_ORDERSAPI_POST_ONLY_REJECT_NAME,
              DERIBIT_ORDERSAPI_POST_ONLY_REJECT_FILTER,
              DERIBIT_ORDERSAPI_POST_ONLY_REJECT_TYPE,
              DERIBIT_ORDERSAPI_POST_ONLY_REJECT_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_POST_ONLY_REJECT_MASK,
              DERIBIT_ORDERSAPI_POST_ONLY_REJECT_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_reserved_10,
            { DERIBIT_ORDERSAPI_RESERVED_10_NAME,
              DERIBIT_ORDERSAPI_RESERVED_10_FILTER,
              DERIBIT_ORDERSAPI_RESERVED_10_TYPE,
              DERIBIT_ORDERSAPI_RESERVED_10_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_RESERVED_10_MASK,
              DERIBIT_ORDERSAPI_RESERVED_10_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_reserved_13,
            { DERIBIT_ORDERSAPI_RESERVED_13_NAME,
              DERIBIT_ORDERSAPI_RESERVED_13_FILTER,
              DERIBIT_ORDERSAPI_RESERVED_13_TYPE,
              DERIBIT_ORDERSAPI_RESERVED_13_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_RESERVED_13_MASK,
              DERIBIT_ORDERSAPI_RESERVED_13_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_reserved_6,
            { DERIBIT_ORDERSAPI_RESERVED_6_NAME,
              DERIBIT_ORDERSAPI_RESERVED_6_FILTER,
              DERIBIT_ORDERSAPI_RESERVED_6_TYPE,
              DERIBIT_ORDERSAPI_RESERVED_6_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_RESERVED_6_MASK,
              DERIBIT_ORDERSAPI_RESERVED_6_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_reserved_7,
            { DERIBIT_ORDERSAPI_RESERVED_7_NAME,
              DERIBIT_ORDERSAPI_RESERVED_7_FILTER,
              DERIBIT_ORDERSAPI_RESERVED_7_TYPE,
              DERIBIT_ORDERSAPI_RESERVED_7_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_RESERVED_7_MASK,
              DERIBIT_ORDERSAPI_RESERVED_7_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_reset_mmp,
            { DERIBIT_ORDERSAPI_RESET_MMP_NAME,
              DERIBIT_ORDERSAPI_RESET_MMP_FILTER,
              DERIBIT_ORDERSAPI_RESET_MMP_TYPE,
              DERIBIT_ORDERSAPI_RESET_MMP_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_RESET_MMP_MASK,
              DERIBIT_ORDERSAPI_RESET_MMP_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_unused_order_flags_0,
            { DERIBIT_ORDERSAPI_UNUSED_ORDER_FLAGS_0_NAME,
              DERIBIT_ORDERSAPI_UNUSED_ORDER_FLAGS_0_FILTER,
              DERIBIT_ORDERSAPI_UNUSED_ORDER_FLAGS_0_TYPE,
              DERIBIT_ORDERSAPI_UNUSED_ORDER_FLAGS_0_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_UNUSED_ORDER_FLAGS_0_MASK,
              DERIBIT_ORDERSAPI_UNUSED_ORDER_FLAGS_0_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_unused_replace_order_flags_0,
            { DERIBIT_ORDERSAPI_UNUSED_REPLACE_ORDER_FLAGS_0_NAME,
              DERIBIT_ORDERSAPI_UNUSED_REPLACE_ORDER_FLAGS_0_FILTER,
              DERIBIT_ORDERSAPI_UNUSED_REPLACE_ORDER_FLAGS_0_TYPE,
              DERIBIT_ORDERSAPI_UNUSED_REPLACE_ORDER_FLAGS_0_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_UNUSED_REPLACE_ORDER_FLAGS_0_MASK,
              DERIBIT_ORDERSAPI_UNUSED_REPLACE_ORDER_FLAGS_0_DESCRIPTION,
              HFILL } },

        /* Bitfields */
        { &hf_deribit_ordersapi_session_flags,
            { DERIBIT_ORDERSAPI_SESSION_FLAGS_NAME,
              DERIBIT_ORDERSAPI_SESSION_FLAGS_FILTER,
              DERIBIT_ORDERSAPI_SESSION_FLAGS_TYPE,
              DERIBIT_ORDERSAPI_SESSION_FLAGS_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_SESSION_FLAGS_MASK,
              DERIBIT_ORDERSAPI_SESSION_FLAGS_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_flags_order_flags,
            { DERIBIT_ORDERSAPI_FLAGS_ORDER_FLAGS_NAME,
              DERIBIT_ORDERSAPI_FLAGS_ORDER_FLAGS_FILTER,
              DERIBIT_ORDERSAPI_FLAGS_ORDER_FLAGS_TYPE,
              DERIBIT_ORDERSAPI_FLAGS_ORDER_FLAGS_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_FLAGS_ORDER_FLAGS_MASK,
              DERIBIT_ORDERSAPI_FLAGS_ORDER_FLAGS_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_flags_replace_order_flags,
            { DERIBIT_ORDERSAPI_FLAGS_REPLACE_ORDER_FLAGS_NAME,
              DERIBIT_ORDERSAPI_FLAGS_REPLACE_ORDER_FLAGS_FILTER,
              DERIBIT_ORDERSAPI_FLAGS_REPLACE_ORDER_FLAGS_TYPE,
              DERIBIT_ORDERSAPI_FLAGS_REPLACE_ORDER_FLAGS_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_FLAGS_REPLACE_ORDER_FLAGS_MASK,
              DERIBIT_ORDERSAPI_FLAGS_REPLACE_ORDER_FLAGS_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_flags_mass_quote_flags,
            { DERIBIT_ORDERSAPI_FLAGS_MASS_QUOTE_FLAGS_NAME,
              DERIBIT_ORDERSAPI_FLAGS_MASS_QUOTE_FLAGS_FILTER,
              DERIBIT_ORDERSAPI_FLAGS_MASS_QUOTE_FLAGS_TYPE,
              DERIBIT_ORDERSAPI_FLAGS_MASS_QUOTE_FLAGS_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_FLAGS_MASS_QUOTE_FLAGS_MASK,
              DERIBIT_ORDERSAPI_FLAGS_MASS_QUOTE_FLAGS_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_bid_flags,
            { DERIBIT_ORDERSAPI_BID_FLAGS_NAME,
              DERIBIT_ORDERSAPI_BID_FLAGS_FILTER,
              DERIBIT_ORDERSAPI_BID_FLAGS_TYPE,
              DERIBIT_ORDERSAPI_BID_FLAGS_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_BID_FLAGS_MASK,
              DERIBIT_ORDERSAPI_BID_FLAGS_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_ask_flags,
            { DERIBIT_ORDERSAPI_ASK_FLAGS_NAME,
              DERIBIT_ORDERSAPI_ASK_FLAGS_FILTER,
              DERIBIT_ORDERSAPI_ASK_FLAGS_TYPE,
              DERIBIT_ORDERSAPI_ASK_FLAGS_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_ASK_FLAGS_MASK,
              DERIBIT_ORDERSAPI_ASK_FLAGS_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_flags_fill_flags,
            { DERIBIT_ORDERSAPI_FLAGS_FILL_FLAGS_NAME,
              DERIBIT_ORDERSAPI_FLAGS_FILL_FLAGS_FILTER,
              DERIBIT_ORDERSAPI_FLAGS_FILL_FLAGS_TYPE,
              DERIBIT_ORDERSAPI_FLAGS_FILL_FLAGS_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_FLAGS_FILL_FLAGS_MASK,
              DERIBIT_ORDERSAPI_FLAGS_FILL_FLAGS_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_flags_multi_part_event_flags,
            { DERIBIT_ORDERSAPI_FLAGS_MULTI_PART_EVENT_FLAGS_NAME,
              DERIBIT_ORDERSAPI_FLAGS_MULTI_PART_EVENT_FLAGS_FILTER,
              DERIBIT_ORDERSAPI_FLAGS_MULTI_PART_EVENT_FLAGS_TYPE,
              DERIBIT_ORDERSAPI_FLAGS_MULTI_PART_EVENT_FLAGS_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_FLAGS_MULTI_PART_EVENT_FLAGS_MASK,
              DERIBIT_ORDERSAPI_FLAGS_MULTI_PART_EVENT_FLAGS_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_flags_cancel_flags,
            { DERIBIT_ORDERSAPI_FLAGS_CANCEL_FLAGS_NAME,
              DERIBIT_ORDERSAPI_FLAGS_CANCEL_FLAGS_FILTER,
              DERIBIT_ORDERSAPI_FLAGS_CANCEL_FLAGS_TYPE,
              DERIBIT_ORDERSAPI_FLAGS_CANCEL_FLAGS_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_FLAGS_CANCEL_FLAGS_MASK,
              DERIBIT_ORDERSAPI_FLAGS_CANCEL_FLAGS_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_flags_order_flags_v10,
            { DERIBIT_ORDERSAPI_FLAGS_ORDER_FLAGS_V10_NAME,
              DERIBIT_ORDERSAPI_FLAGS_ORDER_FLAGS_V10_FILTER,
              DERIBIT_ORDERSAPI_FLAGS_ORDER_FLAGS_V10_TYPE,
              DERIBIT_ORDERSAPI_FLAGS_ORDER_FLAGS_V10_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_FLAGS_ORDER_FLAGS_V10_MASK,
              DERIBIT_ORDERSAPI_FLAGS_ORDER_FLAGS_V10_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_bid_flags_v10,
            { DERIBIT_ORDERSAPI_BID_FLAGS_V10_NAME,
              DERIBIT_ORDERSAPI_BID_FLAGS_V10_FILTER,
              DERIBIT_ORDERSAPI_BID_FLAGS_V10_TYPE,
              DERIBIT_ORDERSAPI_BID_FLAGS_V10_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_BID_FLAGS_V10_MASK,
              DERIBIT_ORDERSAPI_BID_FLAGS_V10_DESCRIPTION,
              HFILL } },
        { &hf_deribit_ordersapi_ask_flags_v10,
            { DERIBIT_ORDERSAPI_ASK_FLAGS_V10_NAME,
              DERIBIT_ORDERSAPI_ASK_FLAGS_V10_FILTER,
              DERIBIT_ORDERSAPI_ASK_FLAGS_V10_TYPE,
              DERIBIT_ORDERSAPI_ASK_FLAGS_V10_DISPLAY,
              NULL,
              DERIBIT_ORDERSAPI_ASK_FLAGS_V10_MASK,
              DERIBIT_ORDERSAPI_ASK_FLAGS_V10_DESCRIPTION,
              HFILL } },
    };

    static int *ett[] = {
        &ett_deribit_ordersapi,
        &ett_deribit_ordersapi_header,
        &ett_deribit_ordersapi_message,
        &ett_deribit_ordersapi_session_flags,
        &ett_deribit_ordersapi_flags_order_flags,
        &ett_deribit_ordersapi_flags_replace_order_flags,
        &ett_deribit_ordersapi_flags_mass_quote_flags,
        &ett_deribit_ordersapi_bid_flags,
        &ett_deribit_ordersapi_ask_flags,
        &ett_deribit_ordersapi_flags_fill_flags,
        &ett_deribit_ordersapi_flags_multi_part_event_flags,
        &ett_deribit_ordersapi_flags_cancel_flags,
        &ett_deribit_ordersapi_flags_order_flags_v10,
        &ett_deribit_ordersapi_bid_flags_v10,
        &ett_deribit_ordersapi_ask_flags_v10,
        &ett_deribit_ordersapi_message_header,
        &ett_deribit_ordersapi_reason,
        &ett_deribit_ordersapi_details,
        &ett_deribit_ordersapi_quantity,
        &ett_deribit_ordersapi_show_qty,
        &ett_deribit_ordersapi_mass_quote_request_message_quotes_groups,
        &ett_deribit_ordersapi_group_size_encoding,
        &ett_deribit_ordersapi_mass_quote_request_message_quotes_group,
        &ett_deribit_ordersapi_bid_qty,
        &ett_deribit_ordersapi_ask_qty,
        &ett_deribit_ordersapi_total_filled,
        &ett_deribit_ordersapi_visible_qty,
        &ett_deribit_ordersapi_new_order_response_message_fills_groups,
        &ett_deribit_ordersapi_new_order_response_message_fills_group,
        &ett_deribit_ordersapi_fill_qty,
        &ett_deribit_ordersapi_new_order_response_message_legs_groups,
        &ett_deribit_ordersapi_new_order_response_message_legs_group,
        &ett_deribit_ordersapi_amend_order_response_message_fills_groups,
        &ett_deribit_ordersapi_amend_order_response_message_fills_group,
        &ett_deribit_ordersapi_amend_order_response_message_legs_groups,
        &ett_deribit_ordersapi_amend_order_response_message_legs_group,
        &ett_deribit_ordersapi_mass_quote_response_message_quotes_groups,
        &ett_deribit_ordersapi_mass_quote_response_message_quotes_group,
        &ett_deribit_ordersapi_bid_filled_qty,
        &ett_deribit_ordersapi_ask_filled_qty,
        &ett_deribit_ordersapi_mass_quote_response_message_bid_fills_groups,
        &ett_deribit_ordersapi_mass_quote_response_message_bid_fills_group,
        &ett_deribit_ordersapi_mass_quote_response_message_ask_fills_groups,
        &ett_deribit_ordersapi_mass_quote_response_message_ask_fills_group,
        &ett_deribit_ordersapi_mass_quote_response_message_legs_groups,
        &ett_deribit_ordersapi_mass_quote_response_message_legs_group,
        &ett_deribit_ordersapi_order_filled_message_fills_groups,
        &ett_deribit_ordersapi_order_filled_message_fills_group,
        &ett_deribit_ordersapi_order_filled_message_legs_groups,
        &ett_deribit_ordersapi_order_filled_message_legs_group,
        &ett_deribit_ordersapi_orders_canceled_message_orders_groups,
        &ett_deribit_ordersapi_orders_canceled_message_orders_group,
        &ett_deribit_ordersapi_order_placed_message_fills_groups,
        &ett_deribit_ordersapi_order_placed_message_fills_group,
        &ett_deribit_ordersapi_order_placed_message_legs_groups,
        &ett_deribit_ordersapi_order_placed_message_legs_group,
        &ett_deribit_ordersapi_mass_quote_orders_placed_message_orders_groups,
        &ett_deribit_ordersapi_mass_quote_orders_placed_message_orders_group,
        &ett_deribit_ordersapi_mass_quote_orders_placed_message_fills_groups,
        &ett_deribit_ordersapi_mass_quote_orders_placed_message_fills_group,
        &ett_deribit_ordersapi_mass_quote_orders_placed_message_legs_groups,
        &ett_deribit_ordersapi_mass_quote_orders_placed_message_legs_group,
        &ett_deribit_ordersapi_mass_quote_request_message_quotes_groups_v10,
        &ett_deribit_ordersapi_mass_quote_request_message_quotes_group_v10,
    };

    static ei_register_info ei[] = {
        { &ei_deribit_ordersapi_length,
            { DERIBIT_ORDERSAPI_LENGTH_EXPERT_FILTER,
              DERIBIT_ORDERSAPI_LENGTH_EXPERT_GROUP,
              DERIBIT_ORDERSAPI_LENGTH_EXPERT_SEVERITY,
              DERIBIT_ORDERSAPI_LENGTH_EXPERT_SUMMARY,
              EXPFILL } },
    };

    proto_deribit_ordersapi = proto_register_protocol(DERIBIT_ORDERSAPI_PROTOCOL_NAME, DERIBIT_ORDERSAPI_PROTOCOL_SHORT, DERIBIT_ORDERSAPI_PROTOCOL_FILTER);

    proto_register_field_array(proto_deribit_ordersapi, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_module_t *expert_deribit_ordersapi = expert_register_protocol(proto_deribit_ordersapi);
    expert_register_field_array(expert_deribit_ordersapi, ei, array_length(ei));

    module_t *preferences = prefs_register_protocol(proto_deribit_ordersapi, NULL);

    prefs_register_enum_preference(
        preferences,
        DERIBIT_ORDERSAPI_VERSION_PREFERENCE_NAME,
        DERIBIT_ORDERSAPI_VERSION_PREFERENCE_TITLE,
        DERIBIT_ORDERSAPI_VERSION_PREFERENCE_DESCRIPTION,
        &deribit_ordersapi_pref_version,
        deribit_ordersapi_version_vals,
        false);

    prefs_register_bool_preference(
        preferences,
        DERIBIT_ORDERSAPI_SHOW_HEADERS_PREFERENCE_NAME,
        DERIBIT_ORDERSAPI_SHOW_HEADERS_PREFERENCE_TITLE,
        DERIBIT_ORDERSAPI_SHOW_HEADERS_PREFERENCE_DESCRIPTION,
        &deribit_ordersapi_show_headers);

    prefs_register_bool_preference(
        preferences,
        DERIBIT_ORDERSAPI_SHOW_APPLICATION_MESSAGES_PREFERENCE_NAME,
        DERIBIT_ORDERSAPI_SHOW_APPLICATION_MESSAGES_PREFERENCE_TITLE,
        DERIBIT_ORDERSAPI_SHOW_APPLICATION_MESSAGES_PREFERENCE_DESCRIPTION,
        &deribit_ordersapi_show_application_messages);

    prefs_register_bool_preference(
        preferences,
        DERIBIT_ORDERSAPI_SHOW_STRUCTS_PREFERENCE_NAME,
        DERIBIT_ORDERSAPI_SHOW_STRUCTS_PREFERENCE_TITLE,
        DERIBIT_ORDERSAPI_SHOW_STRUCTS_PREFERENCE_DESCRIPTION,
        &deribit_ordersapi_show_structs);

    prefs_register_uint_preference(
        preferences,
        DERIBIT_ORDERSAPI_DECIMAL_PREFERENCE_NAME,
        DERIBIT_ORDERSAPI_DECIMAL_PREFERENCE_TITLE,
        DERIBIT_ORDERSAPI_DECIMAL_PREFERENCE_DESCRIPTION,
        10,
        &deribit_ordersapi_pref_decimal_places);

    prefs_register_bool_preference(
        preferences,
        DERIBIT_ORDERSAPI_INDEXES_PREFERENCE_NAME,
        DERIBIT_ORDERSAPI_INDEXES_PREFERENCE_TITLE,
        DERIBIT_ORDERSAPI_INDEXES_PREFERENCE_DESCRIPTION,
        &deribit_ordersapi_pref_show_indexes);

    range_convert_str(
        wmem_epan_scope(),
        &deribit_ordersapi_pref_ports,
        DERIBIT_ORDERSAPI_PORTS_PREFERENCE_DEFAULT,
        DERIBIT_ORDERSAPI_PORTS_PREFERENCE_MAXIMUM);
    prefs_register_range_preference(
        preferences,
        DERIBIT_ORDERSAPI_PORTS_PREFERENCE_NAME,
        DERIBIT_ORDERSAPI_PORTS_PREFERENCE_TITLE,
        DERIBIT_ORDERSAPI_PORTS_PREFERENCE_DESCRIPTION,
        &deribit_ordersapi_pref_ports,
        DERIBIT_ORDERSAPI_PORTS_PREFERENCE_MAXIMUM);

    deribit_ordersapi_handle = register_dissector(DERIBIT_ORDERSAPI_PROTOCOL_FILTER, dissect_deribit_ordersapi, proto_deribit_ordersapi);
}

void
proto_reg_handoff_deribit_ordersapi(void)
{
    heur_dissector_add("tcp", dissect_deribit_ordersapi_heur, "Deribit OrdersApi over TCP",
        "deribit_ordersapi_tcp", proto_deribit_ordersapi, HEURISTIC_ENABLE);

    dissector_add_for_decode_as("tcp.port", deribit_ordersapi_handle);
}
