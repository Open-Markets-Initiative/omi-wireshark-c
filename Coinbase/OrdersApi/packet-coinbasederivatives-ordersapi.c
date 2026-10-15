/* packet-coinbasederivatives-ordersapi.c
 * Routines for CoinbaseDerivatives OrdersApi dissection
 *
 * Aggregated protocol versions: 1.8, 1.7, 1.6, 1.5, 1.4, 1.3
 * Version selection: automatic by send time, or forced by preference
 *
 * Generated from the Omi binary model library
 *
 * Models:
 *   Coinbase.CoinbaseDerivatives.OrdersApi.Sbe.v1.8
 *   Coinbase.CoinbaseDerivatives.OrdersApi.Sbe.v1.7
 *   Coinbase.CoinbaseDerivatives.OrdersApi.Sbe.v1.6
 *   Coinbase.CoinbaseDerivatives.OrdersApi.Sbe.v1.5
 *   Coinbase.CoinbaseDerivatives.OrdersApi.Sbe.v1.4
 *   Coinbase.CoinbaseDerivatives.OrdersApi.Sbe.v1.3
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

void proto_register_coinbasederivatives_ordersapi(void);
void proto_reg_handoff_coinbasederivatives_ordersapi(void);

static dissector_handle_t coinbasederivatives_ordersapi_handle;

static int proto_coinbasederivatives_ordersapi;

/*
 * CoinbaseDerivatives OrdersApi Protocol
 */

#define COINBASEDERIVATIVES_ORDERSAPI_PROTOCOL_NAME "CoinbaseDerivatives OrdersApi"
#define COINBASEDERIVATIVES_ORDERSAPI_PROTOCOL_SHORT "COINBASEDERIVATIVES.ORDERSAPI"
#define COINBASEDERIVATIVES_ORDERSAPI_PROTOCOL_FILTER "coinbasederivatives.ordersapi"

/*
 * CoinbaseDerivatives OrdersApi Header
 */

#define COINBASEDERIVATIVES_ORDERSAPI_HEADER_SIZE 32 /* Sbe Message */

/*
 * CoinbaseDerivatives OrdersApi Field Handles
 */

static int hf_coinbasederivatives_ordersapi_account;
static int hf_coinbasederivatives_ordersapi_available_qty;
static int hf_coinbasederivatives_ordersapi_begin_exec_id;
static int hf_coinbasederivatives_ordersapi_block_length;
static int hf_coinbasederivatives_ordersapi_cancel_order_reject_details;
static int hf_coinbasederivatives_ordersapi_cancel_order_reject_reason;
static int hf_coinbasederivatives_ordersapi_cancel_reason;
static int hf_coinbasederivatives_ordersapi_canceled_count;
static int hf_coinbasederivatives_ordersapi_client_order_id;
static int hf_coinbasederivatives_ordersapi_correlation_id;
static int hf_coinbasederivatives_ordersapi_current_session_only;
static int hf_coinbasederivatives_ordersapi_data_length;
static int hf_coinbasederivatives_ordersapi_data_value;
static int hf_coinbasederivatives_ordersapi_details;
static int hf_coinbasederivatives_ordersapi_details_string_55;
static int hf_coinbasederivatives_ordersapi_end_exec_id;
static int hf_coinbasederivatives_ordersapi_error_message;
static int hf_coinbasederivatives_ordersapi_event_resend_reject_details;
static int hf_coinbasederivatives_ordersapi_exec_id;
static int hf_coinbasederivatives_ordersapi_fill_price;
static int hf_coinbasederivatives_ordersapi_fill_price_v13;
static int hf_coinbasederivatives_ordersapi_fill_qty;
static int hf_coinbasederivatives_ordersapi_filled_vwap;
static int hf_coinbasederivatives_ordersapi_filled_vwap_v13;
static int hf_coinbasederivatives_ordersapi_flags;
static int hf_coinbasederivatives_ordersapi_flags_v15;
static int hf_coinbasederivatives_ordersapi_from_sequence_number;
static int hf_coinbasederivatives_ordersapi_gap_fill_padding;
static int hf_coinbasederivatives_ordersapi_good_til_date;
static int hf_coinbasederivatives_ordersapi_heartbeat_interval_seconds;
static int hf_coinbasederivatives_ordersapi_instrument_id;
static int hf_coinbasederivatives_ordersapi_instrument_status;
static int hf_coinbasederivatives_ordersapi_is_aggressor;
static int hf_coinbasederivatives_ordersapi_is_last_message;
static int hf_coinbasederivatives_ordersapi_is_resend;
static int hf_coinbasederivatives_ordersapi_last_exec_id;
static int hf_coinbasederivatives_ordersapi_last_processed_fill_id;
static int hf_coinbasederivatives_ordersapi_last_processed_seq_no;
static int hf_coinbasederivatives_ordersapi_leg_1_fill_price;
static int hf_coinbasederivatives_ordersapi_leg_1_fill_price_v13;
static int hf_coinbasederivatives_ordersapi_leg_2_fill_price;
static int hf_coinbasederivatives_ordersapi_leg_2_fill_price_v13;
static int hf_coinbasederivatives_ordersapi_limit_price;
static int hf_coinbasederivatives_ordersapi_limit_price_v13;
static int hf_coinbasederivatives_ordersapi_match_id;
static int hf_coinbasederivatives_ordersapi_message_length;
static int hf_coinbasederivatives_ordersapi_min_qty;
static int hf_coinbasederivatives_ordersapi_new_limit_price;
static int hf_coinbasederivatives_ordersapi_new_limit_price_v13;
static int hf_coinbasederivatives_ordersapi_new_quantity;
static int hf_coinbasederivatives_ordersapi_new_sequence_number;
static int hf_coinbasederivatives_ordersapi_num_users_affected;
static int hf_coinbasederivatives_ordersapi_only_current_session;
static int hf_coinbasederivatives_ordersapi_order_id;
static int hf_coinbasederivatives_ordersapi_order_id_optional;
static int hf_coinbasederivatives_ordersapi_order_reject_details;
static int hf_coinbasederivatives_ordersapi_order_reject_reason;
static int hf_coinbasederivatives_ordersapi_padding;
static int hf_coinbasederivatives_ordersapi_password;
static int hf_coinbasederivatives_ordersapi_post_only;
static int hf_coinbasederivatives_ordersapi_product_id;
static int hf_coinbasederivatives_ordersapi_protocol_id;
static int hf_coinbasederivatives_ordersapi_quantity;
static int hf_coinbasederivatives_ordersapi_reason;
static int hf_coinbasederivatives_ordersapi_reason_string_64;
static int hf_coinbasederivatives_ordersapi_receive_time;
static int hf_coinbasederivatives_ordersapi_ref_sequence_number;
static int hf_coinbasederivatives_ordersapi_reject_reason;
static int hf_coinbasederivatives_ordersapi_request_time;
static int hf_coinbasederivatives_ordersapi_request_trading_lock;
static int hf_coinbasederivatives_ordersapi_resend_reject_reason;
static int hf_coinbasederivatives_ordersapi_resent_event_count;
static int hf_coinbasederivatives_ordersapi_reserved;
static int hf_coinbasederivatives_ordersapi_reserved_7;
static int hf_coinbasederivatives_ordersapi_reserved_byte;
static int hf_coinbasederivatives_ordersapi_reset_seq_num;
static int hf_coinbasederivatives_ordersapi_schema_id;
static int hf_coinbasederivatives_ordersapi_security_type;
static int hf_coinbasederivatives_ordersapi_send_time_epoch_nanos;
static int hf_coinbasederivatives_ordersapi_sequence_number;
static int hf_coinbasederivatives_ordersapi_server_time;
static int hf_coinbasederivatives_ordersapi_side;
static int hf_coinbasederivatives_ordersapi_symbol;
static int hf_coinbasederivatives_ordersapi_template_id;
static int hf_coinbasederivatives_ordersapi_time_in_force;
static int hf_coinbasederivatives_ordersapi_timestamp;
static int hf_coinbasederivatives_ordersapi_to_sequence_number;
static int hf_coinbasederivatives_ordersapi_total_filled;
static int hf_coinbasederivatives_ordersapi_trader;
static int hf_coinbasederivatives_ordersapi_trading_instrument_status;
static int hf_coinbasederivatives_ordersapi_trading_lock_applied;
static int hf_coinbasederivatives_ordersapi_username;
static int hf_coinbasederivatives_ordersapi_version;

/*
 * CoinbaseDerivatives OrdersApi Subtrees
 */

static int ett_coinbasederivatives_ordersapi;
static int ett_coinbasederivatives_ordersapi_header;
static int ett_coinbasederivatives_ordersapi_message;
static int ett_coinbasederivatives_ordersapi_flags;
static int ett_coinbasederivatives_ordersapi_flags_v15;
static int ett_coinbasederivatives_ordersapi_message_header;
static int ett_coinbasederivatives_ordersapi_data;
static int ett_coinbasederivatives_ordersapi_message_header_v15;

/*
 * CoinbaseDerivatives OrdersApi Expert Information
 */

/* Message length does not account for the parsed fields */
#define COINBASEDERIVATIVES_ORDERSAPI_LENGTH_EXPERT_FILTER "coinbasederivatives.ordersapi.length.invalid"
#define COINBASEDERIVATIVES_ORDERSAPI_LENGTH_EXPERT_GROUP PI_MALFORMED
#define COINBASEDERIVATIVES_ORDERSAPI_LENGTH_EXPERT_SEVERITY PI_ERROR
#define COINBASEDERIVATIVES_ORDERSAPI_LENGTH_EXPERT_SUMMARY "Message length does not account for the parsed fields"

static expert_field ei_coinbasederivatives_ordersapi_length;

/*
 * CoinbaseDerivatives OrdersApi Preferences
 */

#define COINBASEDERIVATIVES_ORDERSAPI_VERSION_PREFERENCE_NAME "version"
#define COINBASEDERIVATIVES_ORDERSAPI_VERSION_PREFERENCE_TITLE "Protocol version"
#define COINBASEDERIVATIVES_ORDERSAPI_VERSION_PREFERENCE_DESCRIPTION "Version used when dissecting, Automatic selects by the packet send time"

#define COINBASEDERIVATIVES_ORDERSAPI_VERSION_AUTOMATIC 0
#define COINBASEDERIVATIVES_ORDERSAPI_VERSION_1_8     1
#define COINBASEDERIVATIVES_ORDERSAPI_VERSION_1_7     2
#define COINBASEDERIVATIVES_ORDERSAPI_VERSION_1_6     3
#define COINBASEDERIVATIVES_ORDERSAPI_VERSION_1_5     4
#define COINBASEDERIVATIVES_ORDERSAPI_VERSION_1_4     5
#define COINBASEDERIVATIVES_ORDERSAPI_VERSION_1_3     6

static const enum_val_t coinbasederivatives_ordersapi_version_vals[] = {
    { "automatic", "Automatic (by send time)", COINBASEDERIVATIVES_ORDERSAPI_VERSION_AUTOMATIC },
    { "v1.8", "1.8", COINBASEDERIVATIVES_ORDERSAPI_VERSION_1_8 },
    { "v1.7", "1.7", COINBASEDERIVATIVES_ORDERSAPI_VERSION_1_7 },
    { "v1.6", "1.6", COINBASEDERIVATIVES_ORDERSAPI_VERSION_1_6 },
    { "v1.5", "1.5", COINBASEDERIVATIVES_ORDERSAPI_VERSION_1_5 },
    { "v1.4", "1.4", COINBASEDERIVATIVES_ORDERSAPI_VERSION_1_4 },
    { "v1.3", "1.3", COINBASEDERIVATIVES_ORDERSAPI_VERSION_1_3 },
    { NULL, NULL, 0 }
};

/* The version a frame was read with, for the protocol line */
static const char *
coinbasederivatives_ordersapi_version_name(int version)
{
    switch (version) {
    case COINBASEDERIVATIVES_ORDERSAPI_VERSION_1_8:
        return "1.8";
    case COINBASEDERIVATIVES_ORDERSAPI_VERSION_1_7:
        return "1.7";
    case COINBASEDERIVATIVES_ORDERSAPI_VERSION_1_6:
        return "1.6";
    case COINBASEDERIVATIVES_ORDERSAPI_VERSION_1_5:
        return "1.5";
    case COINBASEDERIVATIVES_ORDERSAPI_VERSION_1_4:
        return "1.4";
    case COINBASEDERIVATIVES_ORDERSAPI_VERSION_1_3:
        return "1.3";
    }

    return "";
}

static int coinbasederivatives_ordersapi_pref_version = COINBASEDERIVATIVES_ORDERSAPI_VERSION_AUTOMATIC;

/* Version effective times, seconds since the unix epoch */
#define COINBASEDERIVATIVES_ORDERSAPI_EFFECTIVE_1_8 UINT64_C(1757030400) /* 2025-09-05 */
#define COINBASEDERIVATIVES_ORDERSAPI_EFFECTIVE_1_7 UINT64_C(1751328000) /* 2025-07-01 */
#define COINBASEDERIVATIVES_ORDERSAPI_EFFECTIVE_1_6 UINT64_C(1697155200) /* 2023-10-13 */
#define COINBASEDERIVATIVES_ORDERSAPI_EFFECTIVE_1_5 UINT64_C(1649894400) /* 2022-04-14 */
#define COINBASEDERIVATIVES_ORDERSAPI_EFFECTIVE_1_4 UINT64_C(1595808000) /* 2020-07-27 */

/* Show preferences, one per message and struct */
#define COINBASEDERIVATIVES_ORDERSAPI_SHOW_HEADERS_PREFERENCE_NAME "show.headers"
#define COINBASEDERIVATIVES_ORDERSAPI_SHOW_HEADERS_PREFERENCE_TITLE "Show Headers"
#define COINBASEDERIVATIVES_ORDERSAPI_SHOW_HEADERS_PREFERENCE_DESCRIPTION "Show Headers in the protocol tree"

#define COINBASEDERIVATIVES_ORDERSAPI_SHOW_SCHEMA_MESSAGES_PREFERENCE_NAME "show.schemamessages"
#define COINBASEDERIVATIVES_ORDERSAPI_SHOW_SCHEMA_MESSAGES_PREFERENCE_TITLE "Show Schema Messages"
#define COINBASEDERIVATIVES_ORDERSAPI_SHOW_SCHEMA_MESSAGES_PREFERENCE_DESCRIPTION "Show Schema Messages in the protocol tree"

#define COINBASEDERIVATIVES_ORDERSAPI_SHOW_APPLICATION_MESSAGES_PREFERENCE_NAME "show.applicationmessages"
#define COINBASEDERIVATIVES_ORDERSAPI_SHOW_APPLICATION_MESSAGES_PREFERENCE_TITLE "Show Application Messages"
#define COINBASEDERIVATIVES_ORDERSAPI_SHOW_APPLICATION_MESSAGES_PREFERENCE_DESCRIPTION "Show Application Messages in the protocol tree"

#define COINBASEDERIVATIVES_ORDERSAPI_SHOW_STRUCTS_PREFERENCE_NAME "show.structs"
#define COINBASEDERIVATIVES_ORDERSAPI_SHOW_STRUCTS_PREFERENCE_TITLE "Show Structs"
#define COINBASEDERIVATIVES_ORDERSAPI_SHOW_STRUCTS_PREFERENCE_DESCRIPTION "Show Structs in the protocol tree"

static bool coinbasederivatives_ordersapi_show_headers = true;
static bool coinbasederivatives_ordersapi_show_schema_messages = true;
static bool coinbasederivatives_ordersapi_show_application_messages = true;
static bool coinbasederivatives_ordersapi_show_structs = true;

/* Decimal places shown, the wire precision by default */
#define COINBASEDERIVATIVES_ORDERSAPI_DECIMAL_PREFERENCE_NAME "decimal.places"
#define COINBASEDERIVATIVES_ORDERSAPI_DECIMAL_PREFERENCE_TITLE "Decimal places"
#define COINBASEDERIVATIVES_ORDERSAPI_DECIMAL_PREFERENCE_DESCRIPTION "Decimal places shown for scaled fields, the default is the full wire precision"

static unsigned coinbasederivatives_ordersapi_pref_decimal_places = 9;

/*
 * CoinbaseDerivatives OrdersApi Methods
 */

/* Select the protocol version, from the preference, the
   schema the frame declares, or the capture clock in seconds
   since the unix epoch */
static int
coinbasederivatives_ordersapi_version(uint64_t seconds)
{
    if (coinbasederivatives_ordersapi_pref_version != COINBASEDERIVATIVES_ORDERSAPI_VERSION_AUTOMATIC) {
        return coinbasederivatives_ordersapi_pref_version;
    }

    if (seconds >= COINBASEDERIVATIVES_ORDERSAPI_EFFECTIVE_1_8) {
        return COINBASEDERIVATIVES_ORDERSAPI_VERSION_1_8;
    }

    if (seconds >= COINBASEDERIVATIVES_ORDERSAPI_EFFECTIVE_1_7) {
        return COINBASEDERIVATIVES_ORDERSAPI_VERSION_1_7;
    }

    if (seconds >= COINBASEDERIVATIVES_ORDERSAPI_EFFECTIVE_1_6) {
        return COINBASEDERIVATIVES_ORDERSAPI_VERSION_1_6;
    }

    if (seconds >= COINBASEDERIVATIVES_ORDERSAPI_EFFECTIVE_1_5) {
        return COINBASEDERIVATIVES_ORDERSAPI_VERSION_1_5;
    }

    if (seconds >= COINBASEDERIVATIVES_ORDERSAPI_EFFECTIVE_1_4) {
        return COINBASEDERIVATIVES_ORDERSAPI_VERSION_1_4;
    }

    return COINBASEDERIVATIVES_ORDERSAPI_VERSION_1_3;
}

/* Cap the fraction at the preferred decimal places */
static void
coinbasederivatives_ordersapi_decimal_places(char *buf)
{
    char *point = strchr(buf, '.');

    if (point == NULL) {
        return;
    }

    unsigned places = coinbasederivatives_ordersapi_pref_decimal_places;

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
coinbasederivatives_ordersapi_format_decimal_9_64(char *buf, uint64_t raw)
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

    coinbasederivatives_ordersapi_decimal_places(buf);
}

/* Format an implied 9 decimal place value */
static void
coinbasederivatives_ordersapi_format_decimal_9_64_nullable(char *buf, uint64_t raw)
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

    coinbasederivatives_ordersapi_decimal_places(buf);
}

/* Format a nullable integer, the label alone for the sentinel */
static void
coinbasederivatives_ordersapi_format_nullable_32(char *buf, uint32_t raw)
{
    int64_t value = (int32_t)raw;

    if (value == 0) {
        snprintf(buf, ITEM_LABEL_LENGTH, "%s", "No Value");
        return;
    }

    snprintf(buf, ITEM_LABEL_LENGTH, "%" PRId64, value);
}

/* Format a nullable integer, the label alone for the sentinel */
static void
coinbasederivatives_ordersapi_format_nullable_64(char *buf, uint64_t raw)
{
    int64_t value = (int64_t)raw;

    if (value == INT64_MIN) {
        snprintf(buf, ITEM_LABEL_LENGTH, "%s", "No Value");
        return;
    }

    snprintf(buf, ITEM_LABEL_LENGTH, "%" PRId64, value);
}

/*
 * CoinbaseDerivatives OrdersApi Fields
 */

/* Account */
#define COINBASEDERIVATIVES_ORDERSAPI_ACCOUNT_NAME        "Account"
#define COINBASEDERIVATIVES_ORDERSAPI_ACCOUNT_DESCRIPTION "Account, a zero padded ascii string"
#define COINBASEDERIVATIVES_ORDERSAPI_ACCOUNT_FILTER      "coinbasederivatives.ordersapi.account"
#define COINBASEDERIVATIVES_ORDERSAPI_ACCOUNT_TYPE        FT_STRING
#define COINBASEDERIVATIVES_ORDERSAPI_ACCOUNT_DISPLAY     BASE_NONE
#define COINBASEDERIVATIVES_ORDERSAPI_ACCOUNT_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_ACCOUNT_ENCODING    ENC_ASCII
#define COINBASEDERIVATIVES_ORDERSAPI_ACCOUNT_SIZE        16

static unsigned
parse_coinbasederivatives_ordersapi_account(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_account, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_ACCOUNT_SIZE, COINBASEDERIVATIVES_ORDERSAPI_ACCOUNT_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_ACCOUNT_SIZE;
}

/* Available Qty */
#define COINBASEDERIVATIVES_ORDERSAPI_AVAILABLE_QTY_NAME        "Available Qty"
#define COINBASEDERIVATIVES_ORDERSAPI_AVAILABLE_QTY_DESCRIPTION "availableQty"
#define COINBASEDERIVATIVES_ORDERSAPI_AVAILABLE_QTY_FILTER      "coinbasederivatives.ordersapi.availableqty"
#define COINBASEDERIVATIVES_ORDERSAPI_AVAILABLE_QTY_TYPE        FT_INT32
#define COINBASEDERIVATIVES_ORDERSAPI_AVAILABLE_QTY_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_AVAILABLE_QTY_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_AVAILABLE_QTY_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_AVAILABLE_QTY_SIZE        4

static unsigned
parse_coinbasederivatives_ordersapi_available_qty(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_available_qty, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_AVAILABLE_QTY_SIZE, COINBASEDERIVATIVES_ORDERSAPI_AVAILABLE_QTY_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_AVAILABLE_QTY_SIZE;
}

/* Begin Exec Id */
#define COINBASEDERIVATIVES_ORDERSAPI_BEGIN_EXEC_ID_NAME        "Begin Exec Id"
#define COINBASEDERIVATIVES_ORDERSAPI_BEGIN_EXEC_ID_DESCRIPTION "beginExecId"
#define COINBASEDERIVATIVES_ORDERSAPI_BEGIN_EXEC_ID_FILTER      "coinbasederivatives.ordersapi.beginexecid"
#define COINBASEDERIVATIVES_ORDERSAPI_BEGIN_EXEC_ID_TYPE        FT_INT64
#define COINBASEDERIVATIVES_ORDERSAPI_BEGIN_EXEC_ID_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_BEGIN_EXEC_ID_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_BEGIN_EXEC_ID_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_BEGIN_EXEC_ID_SIZE        8

static unsigned
parse_coinbasederivatives_ordersapi_begin_exec_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_begin_exec_id, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_BEGIN_EXEC_ID_SIZE, COINBASEDERIVATIVES_ORDERSAPI_BEGIN_EXEC_ID_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_BEGIN_EXEC_ID_SIZE;
}

/* Block Length */
#define COINBASEDERIVATIVES_ORDERSAPI_BLOCK_LENGTH_NAME        "Block Length"
#define COINBASEDERIVATIVES_ORDERSAPI_BLOCK_LENGTH_DESCRIPTION "Length of the root of the message contained before repeating groups or variable-length fields"
#define COINBASEDERIVATIVES_ORDERSAPI_BLOCK_LENGTH_FILTER      "coinbasederivatives.ordersapi.blocklength"
#define COINBASEDERIVATIVES_ORDERSAPI_BLOCK_LENGTH_TYPE        FT_UINT16
#define COINBASEDERIVATIVES_ORDERSAPI_BLOCK_LENGTH_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_BLOCK_LENGTH_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_BLOCK_LENGTH_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_BLOCK_LENGTH_SIZE        2

static unsigned
parse_coinbasederivatives_ordersapi_block_length(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_block_length, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_BLOCK_LENGTH_SIZE, COINBASEDERIVATIVES_ORDERSAPI_BLOCK_LENGTH_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_BLOCK_LENGTH_SIZE;
}

/* Cancel Order Reject Details */
#define COINBASEDERIVATIVES_ORDERSAPI_CANCEL_ORDER_REJECT_DETAILS_NAME        "Cancel Order Reject Details"
#define COINBASEDERIVATIVES_ORDERSAPI_CANCEL_ORDER_REJECT_DETAILS_DESCRIPTION "details"
#define COINBASEDERIVATIVES_ORDERSAPI_CANCEL_ORDER_REJECT_DETAILS_FILTER      "coinbasederivatives.ordersapi.cancelorderrejectdetails"
#define COINBASEDERIVATIVES_ORDERSAPI_CANCEL_ORDER_REJECT_DETAILS_TYPE        FT_STRING
#define COINBASEDERIVATIVES_ORDERSAPI_CANCEL_ORDER_REJECT_DETAILS_DISPLAY     BASE_NONE
#define COINBASEDERIVATIVES_ORDERSAPI_CANCEL_ORDER_REJECT_DETAILS_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_CANCEL_ORDER_REJECT_DETAILS_ENCODING    ENC_ASCII
#define COINBASEDERIVATIVES_ORDERSAPI_CANCEL_ORDER_REJECT_DETAILS_SIZE        31

static unsigned
parse_coinbasederivatives_ordersapi_cancel_order_reject_details(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_cancel_order_reject_details, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_CANCEL_ORDER_REJECT_DETAILS_SIZE, COINBASEDERIVATIVES_ORDERSAPI_CANCEL_ORDER_REJECT_DETAILS_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_CANCEL_ORDER_REJECT_DETAILS_SIZE;
}

/* Cancel Order Reject Reason */
#define COINBASEDERIVATIVES_ORDERSAPI_CANCEL_ORDER_REJECT_REASON_NAME        "Cancel Order Reject Reason"
#define COINBASEDERIVATIVES_ORDERSAPI_CANCEL_ORDER_REJECT_REASON_DESCRIPTION "rejectReason"
#define COINBASEDERIVATIVES_ORDERSAPI_CANCEL_ORDER_REJECT_REASON_FILTER      "coinbasederivatives.ordersapi.cancelorderrejectreason"
#define COINBASEDERIVATIVES_ORDERSAPI_CANCEL_ORDER_REJECT_REASON_TYPE        FT_UINT8
#define COINBASEDERIVATIVES_ORDERSAPI_CANCEL_ORDER_REJECT_REASON_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_CANCEL_ORDER_REJECT_REASON_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_CANCEL_ORDER_REJECT_REASON_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_CANCEL_ORDER_REJECT_REASON_SIZE        1

static const value_string coinbasederivatives_ordersapi_cancel_order_reject_reason_vals[] = {
    { 1, "Error" },
    { 2, "Unknown Order" },
    { 3, "Order Filled" },
    { 0, NULL }
};

static unsigned
parse_coinbasederivatives_ordersapi_cancel_order_reject_reason(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_cancel_order_reject_reason, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_CANCEL_ORDER_REJECT_REASON_SIZE, COINBASEDERIVATIVES_ORDERSAPI_CANCEL_ORDER_REJECT_REASON_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_CANCEL_ORDER_REJECT_REASON_SIZE;
}

/* Cancel Reason */
#define COINBASEDERIVATIVES_ORDERSAPI_CANCEL_REASON_NAME        "Cancel Reason"
#define COINBASEDERIVATIVES_ORDERSAPI_CANCEL_REASON_DESCRIPTION "cancelReason"
#define COINBASEDERIVATIVES_ORDERSAPI_CANCEL_REASON_FILTER      "coinbasederivatives.ordersapi.cancelreason"
#define COINBASEDERIVATIVES_ORDERSAPI_CANCEL_REASON_TYPE        FT_UINT8
#define COINBASEDERIVATIVES_ORDERSAPI_CANCEL_REASON_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_CANCEL_REASON_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_CANCEL_REASON_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_CANCEL_REASON_SIZE        1

static const value_string coinbasederivatives_ordersapi_cancel_reason_vals[] = {
    { 0, "Expired" },
    { 1, "Canceled By User" },
    { 2, "Self Match Prevention" },
    { 3, "Client Disconnect" },
    { 4, "Price Limit" },
    { 5, "Admin Cancel" },
    { 6, "Mass Cancel" },
    { 7, "Stream Replaced" },
    { 8, "Active Limit Exceeded" },
    { 0, NULL }
};

static unsigned
parse_coinbasederivatives_ordersapi_cancel_reason(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_cancel_reason, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_CANCEL_REASON_SIZE, COINBASEDERIVATIVES_ORDERSAPI_CANCEL_REASON_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_CANCEL_REASON_SIZE;
}

/* Canceled Count */
#define COINBASEDERIVATIVES_ORDERSAPI_CANCELED_COUNT_NAME        "Canceled Count"
#define COINBASEDERIVATIVES_ORDERSAPI_CANCELED_COUNT_DESCRIPTION "canceledCount"
#define COINBASEDERIVATIVES_ORDERSAPI_CANCELED_COUNT_FILTER      "coinbasederivatives.ordersapi.canceledcount"
#define COINBASEDERIVATIVES_ORDERSAPI_CANCELED_COUNT_TYPE        FT_INT32
#define COINBASEDERIVATIVES_ORDERSAPI_CANCELED_COUNT_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_CANCELED_COUNT_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_CANCELED_COUNT_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_CANCELED_COUNT_SIZE        4

static unsigned
parse_coinbasederivatives_ordersapi_canceled_count(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_canceled_count, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_CANCELED_COUNT_SIZE, COINBASEDERIVATIVES_ORDERSAPI_CANCELED_COUNT_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_CANCELED_COUNT_SIZE;
}

/* Client Order Id */
#define COINBASEDERIVATIVES_ORDERSAPI_CLIENT_ORDER_ID_NAME        "Client Order Id"
#define COINBASEDERIVATIVES_ORDERSAPI_CLIENT_ORDER_ID_DESCRIPTION "clientOrderId"
#define COINBASEDERIVATIVES_ORDERSAPI_CLIENT_ORDER_ID_FILTER      "coinbasederivatives.ordersapi.clientorderid"
#define COINBASEDERIVATIVES_ORDERSAPI_CLIENT_ORDER_ID_TYPE        FT_INT64
#define COINBASEDERIVATIVES_ORDERSAPI_CLIENT_ORDER_ID_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_CLIENT_ORDER_ID_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_CLIENT_ORDER_ID_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_CLIENT_ORDER_ID_SIZE        8

static unsigned
parse_coinbasederivatives_ordersapi_client_order_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_client_order_id, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_CLIENT_ORDER_ID_SIZE, COINBASEDERIVATIVES_ORDERSAPI_CLIENT_ORDER_ID_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_CLIENT_ORDER_ID_SIZE;
}

/* Correlation Id */
#define COINBASEDERIVATIVES_ORDERSAPI_CORRELATION_ID_NAME        "Correlation Id"
#define COINBASEDERIVATIVES_ORDERSAPI_CORRELATION_ID_DESCRIPTION "correlationId"
#define COINBASEDERIVATIVES_ORDERSAPI_CORRELATION_ID_FILTER      "coinbasederivatives.ordersapi.correlationid"
#define COINBASEDERIVATIVES_ORDERSAPI_CORRELATION_ID_TYPE        FT_INT64
#define COINBASEDERIVATIVES_ORDERSAPI_CORRELATION_ID_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_CORRELATION_ID_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_CORRELATION_ID_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_CORRELATION_ID_SIZE        8

static unsigned
parse_coinbasederivatives_ordersapi_correlation_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_correlation_id, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_CORRELATION_ID_SIZE, COINBASEDERIVATIVES_ORDERSAPI_CORRELATION_ID_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_CORRELATION_ID_SIZE;
}

/* Current Session Only */
#define COINBASEDERIVATIVES_ORDERSAPI_CURRENT_SESSION_ONLY_NAME        "Current Session Only"
#define COINBASEDERIVATIVES_ORDERSAPI_CURRENT_SESSION_ONLY_DESCRIPTION "currentSessionOnly"
#define COINBASEDERIVATIVES_ORDERSAPI_CURRENT_SESSION_ONLY_FILTER      "coinbasederivatives.ordersapi.currentsessiononly"
#define COINBASEDERIVATIVES_ORDERSAPI_CURRENT_SESSION_ONLY_TYPE        FT_INT8
#define COINBASEDERIVATIVES_ORDERSAPI_CURRENT_SESSION_ONLY_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_CURRENT_SESSION_ONLY_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_CURRENT_SESSION_ONLY_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_CURRENT_SESSION_ONLY_SIZE        1

static const value_string coinbasederivatives_ordersapi_current_session_only_vals[] = {
    { 0, "False" },
    { 1, "True" },
    { 0, NULL }
};

static unsigned
parse_coinbasederivatives_ordersapi_current_session_only(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_current_session_only, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_CURRENT_SESSION_ONLY_SIZE, COINBASEDERIVATIVES_ORDERSAPI_CURRENT_SESSION_ONLY_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_CURRENT_SESSION_ONLY_SIZE;
}

/* Data Length */
#define COINBASEDERIVATIVES_ORDERSAPI_DATA_LENGTH_NAME     "Data Length"
#define COINBASEDERIVATIVES_ORDERSAPI_DATA_LENGTH_FILTER   "coinbasederivatives.ordersapi.datalength"
#define COINBASEDERIVATIVES_ORDERSAPI_DATA_LENGTH_TYPE     FT_UINT8
#define COINBASEDERIVATIVES_ORDERSAPI_DATA_LENGTH_DISPLAY  BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_DATA_LENGTH_MASK     0x0
#define COINBASEDERIVATIVES_ORDERSAPI_DATA_LENGTH_ENCODING ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_DATA_LENGTH_SIZE     1

static unsigned
parse_coinbasederivatives_ordersapi_data_length(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_data_length, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_DATA_LENGTH_SIZE, COINBASEDERIVATIVES_ORDERSAPI_DATA_LENGTH_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_DATA_LENGTH_SIZE;
}

/* Data Value */
#define COINBASEDERIVATIVES_ORDERSAPI_DATA_VALUE_NAME     "Data Value"
#define COINBASEDERIVATIVES_ORDERSAPI_DATA_VALUE_FILTER   "coinbasederivatives.ordersapi.datavalue"
#define COINBASEDERIVATIVES_ORDERSAPI_DATA_VALUE_TYPE     FT_BYTES
#define COINBASEDERIVATIVES_ORDERSAPI_DATA_VALUE_DISPLAY  BASE_NONE
#define COINBASEDERIVATIVES_ORDERSAPI_DATA_VALUE_MASK     0x0
#define COINBASEDERIVATIVES_ORDERSAPI_DATA_VALUE_ENCODING ENC_NA

/* Details */
#define COINBASEDERIVATIVES_ORDERSAPI_DETAILS_NAME        "Details"
#define COINBASEDERIVATIVES_ORDERSAPI_DETAILS_DESCRIPTION "Logout details"
#define COINBASEDERIVATIVES_ORDERSAPI_DETAILS_FILTER      "coinbasederivatives.ordersapi.details"
#define COINBASEDERIVATIVES_ORDERSAPI_DETAILS_TYPE        FT_STRING
#define COINBASEDERIVATIVES_ORDERSAPI_DETAILS_DISPLAY     BASE_NONE
#define COINBASEDERIVATIVES_ORDERSAPI_DETAILS_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_DETAILS_ENCODING    ENC_ASCII
#define COINBASEDERIVATIVES_ORDERSAPI_DETAILS_SIZE        64

static unsigned
parse_coinbasederivatives_ordersapi_details(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_details, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_DETAILS_SIZE, COINBASEDERIVATIVES_ORDERSAPI_DETAILS_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_DETAILS_SIZE;
}

/* Details String 55 */
#define COINBASEDERIVATIVES_ORDERSAPI_DETAILS_STRING_55_NAME        "Details String 55"
#define COINBASEDERIVATIVES_ORDERSAPI_DETAILS_STRING_55_DESCRIPTION "details"
#define COINBASEDERIVATIVES_ORDERSAPI_DETAILS_STRING_55_FILTER      "coinbasederivatives.ordersapi.detailsstring55"
#define COINBASEDERIVATIVES_ORDERSAPI_DETAILS_STRING_55_TYPE        FT_STRING
#define COINBASEDERIVATIVES_ORDERSAPI_DETAILS_STRING_55_DISPLAY     BASE_NONE
#define COINBASEDERIVATIVES_ORDERSAPI_DETAILS_STRING_55_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_DETAILS_STRING_55_ENCODING    ENC_ASCII
#define COINBASEDERIVATIVES_ORDERSAPI_DETAILS_STRING_55_SIZE        55

static unsigned
parse_coinbasederivatives_ordersapi_details_string_55(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_details_string_55, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_DETAILS_STRING_55_SIZE, COINBASEDERIVATIVES_ORDERSAPI_DETAILS_STRING_55_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_DETAILS_STRING_55_SIZE;
}

/* End Exec Id */
#define COINBASEDERIVATIVES_ORDERSAPI_END_EXEC_ID_NAME        "End Exec Id"
#define COINBASEDERIVATIVES_ORDERSAPI_END_EXEC_ID_DESCRIPTION "endExecId"
#define COINBASEDERIVATIVES_ORDERSAPI_END_EXEC_ID_FILTER      "coinbasederivatives.ordersapi.endexecid"
#define COINBASEDERIVATIVES_ORDERSAPI_END_EXEC_ID_TYPE        FT_INT64
#define COINBASEDERIVATIVES_ORDERSAPI_END_EXEC_ID_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_END_EXEC_ID_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_END_EXEC_ID_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_END_EXEC_ID_SIZE        8

static unsigned
parse_coinbasederivatives_ordersapi_end_exec_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_end_exec_id, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_END_EXEC_ID_SIZE, COINBASEDERIVATIVES_ORDERSAPI_END_EXEC_ID_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_END_EXEC_ID_SIZE;
}

/* Error Message */
#define COINBASEDERIVATIVES_ORDERSAPI_ERROR_MESSAGE_NAME        "Error Message"
#define COINBASEDERIVATIVES_ORDERSAPI_ERROR_MESSAGE_DESCRIPTION "errorMessage"
#define COINBASEDERIVATIVES_ORDERSAPI_ERROR_MESSAGE_FILTER      "coinbasederivatives.ordersapi.errormessage"
#define COINBASEDERIVATIVES_ORDERSAPI_ERROR_MESSAGE_TYPE        FT_STRING
#define COINBASEDERIVATIVES_ORDERSAPI_ERROR_MESSAGE_DISPLAY     BASE_NONE
#define COINBASEDERIVATIVES_ORDERSAPI_ERROR_MESSAGE_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_ERROR_MESSAGE_ENCODING    ENC_ASCII
#define COINBASEDERIVATIVES_ORDERSAPI_ERROR_MESSAGE_SIZE        32

static unsigned
parse_coinbasederivatives_ordersapi_error_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_error_message, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_ERROR_MESSAGE_SIZE, COINBASEDERIVATIVES_ORDERSAPI_ERROR_MESSAGE_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_ERROR_MESSAGE_SIZE;
}

/* Event Resend Reject Details */
#define COINBASEDERIVATIVES_ORDERSAPI_EVENT_RESEND_REJECT_DETAILS_NAME        "Event Resend Reject Details"
#define COINBASEDERIVATIVES_ORDERSAPI_EVENT_RESEND_REJECT_DETAILS_DESCRIPTION "details"
#define COINBASEDERIVATIVES_ORDERSAPI_EVENT_RESEND_REJECT_DETAILS_FILTER      "coinbasederivatives.ordersapi.eventresendrejectdetails"
#define COINBASEDERIVATIVES_ORDERSAPI_EVENT_RESEND_REJECT_DETAILS_TYPE        FT_STRING
#define COINBASEDERIVATIVES_ORDERSAPI_EVENT_RESEND_REJECT_DETAILS_DISPLAY     BASE_NONE
#define COINBASEDERIVATIVES_ORDERSAPI_EVENT_RESEND_REJECT_DETAILS_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_EVENT_RESEND_REJECT_DETAILS_ENCODING    ENC_ASCII
#define COINBASEDERIVATIVES_ORDERSAPI_EVENT_RESEND_REJECT_DETAILS_SIZE        23

static unsigned
parse_coinbasederivatives_ordersapi_event_resend_reject_details(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_event_resend_reject_details, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_EVENT_RESEND_REJECT_DETAILS_SIZE, COINBASEDERIVATIVES_ORDERSAPI_EVENT_RESEND_REJECT_DETAILS_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_EVENT_RESEND_REJECT_DETAILS_SIZE;
}

/* Exec Id */
#define COINBASEDERIVATIVES_ORDERSAPI_EXEC_ID_NAME        "Exec Id"
#define COINBASEDERIVATIVES_ORDERSAPI_EXEC_ID_DESCRIPTION "execId"
#define COINBASEDERIVATIVES_ORDERSAPI_EXEC_ID_FILTER      "coinbasederivatives.ordersapi.execid"
#define COINBASEDERIVATIVES_ORDERSAPI_EXEC_ID_TYPE        FT_INT64
#define COINBASEDERIVATIVES_ORDERSAPI_EXEC_ID_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_EXEC_ID_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_EXEC_ID_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_EXEC_ID_SIZE        8

static unsigned
parse_coinbasederivatives_ordersapi_exec_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_exec_id, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_EXEC_ID_SIZE, COINBASEDERIVATIVES_ORDERSAPI_EXEC_ID_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_EXEC_ID_SIZE;
}

/* Fill Price */
#define COINBASEDERIVATIVES_ORDERSAPI_FILL_PRICE_NAME        "Fill Price"
#define COINBASEDERIVATIVES_ORDERSAPI_FILL_PRICE_DESCRIPTION "fillPrice"
#define COINBASEDERIVATIVES_ORDERSAPI_FILL_PRICE_FILTER      "coinbasederivatives.ordersapi.fillprice"
#define COINBASEDERIVATIVES_ORDERSAPI_FILL_PRICE_TYPE        FT_INT64
#define COINBASEDERIVATIVES_ORDERSAPI_FILL_PRICE_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_ORDERSAPI_FILL_PRICE_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_FILL_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_FILL_PRICE_SIZE        8

static unsigned
parse_coinbasederivatives_ordersapi_fill_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_fill_price, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_FILL_PRICE_SIZE, COINBASEDERIVATIVES_ORDERSAPI_FILL_PRICE_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_FILL_PRICE_SIZE;
}

/* Fill Price V13 */
#define COINBASEDERIVATIVES_ORDERSAPI_FILL_PRICE_V13_NAME        "Fill Price"
#define COINBASEDERIVATIVES_ORDERSAPI_FILL_PRICE_V13_DESCRIPTION "fillPrice"
#define COINBASEDERIVATIVES_ORDERSAPI_FILL_PRICE_V13_FILTER      "coinbasederivatives.ordersapi.fillprice"
#define COINBASEDERIVATIVES_ORDERSAPI_FILL_PRICE_V13_TYPE        FT_INT64
#define COINBASEDERIVATIVES_ORDERSAPI_FILL_PRICE_V13_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_FILL_PRICE_V13_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_FILL_PRICE_V13_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_FILL_PRICE_V13_SIZE        8

static unsigned
parse_coinbasederivatives_ordersapi_fill_price_v13(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_fill_price_v13, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_FILL_PRICE_V13_SIZE, COINBASEDERIVATIVES_ORDERSAPI_FILL_PRICE_V13_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_FILL_PRICE_V13_SIZE;
}

/* Fill Qty */
#define COINBASEDERIVATIVES_ORDERSAPI_FILL_QTY_NAME        "Fill Qty"
#define COINBASEDERIVATIVES_ORDERSAPI_FILL_QTY_DESCRIPTION "fillQty"
#define COINBASEDERIVATIVES_ORDERSAPI_FILL_QTY_FILTER      "coinbasederivatives.ordersapi.fillqty"
#define COINBASEDERIVATIVES_ORDERSAPI_FILL_QTY_TYPE        FT_INT32
#define COINBASEDERIVATIVES_ORDERSAPI_FILL_QTY_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_FILL_QTY_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_FILL_QTY_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_FILL_QTY_SIZE        4

static unsigned
parse_coinbasederivatives_ordersapi_fill_qty(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_fill_qty, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_FILL_QTY_SIZE, COINBASEDERIVATIVES_ORDERSAPI_FILL_QTY_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_FILL_QTY_SIZE;
}

/* Filled Vwap */
#define COINBASEDERIVATIVES_ORDERSAPI_FILLED_VWAP_NAME        "Filled Vwap"
#define COINBASEDERIVATIVES_ORDERSAPI_FILLED_VWAP_DESCRIPTION "filledVwap"
#define COINBASEDERIVATIVES_ORDERSAPI_FILLED_VWAP_FILTER      "coinbasederivatives.ordersapi.filledvwap"
#define COINBASEDERIVATIVES_ORDERSAPI_FILLED_VWAP_TYPE        FT_INT64
#define COINBASEDERIVATIVES_ORDERSAPI_FILLED_VWAP_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_ORDERSAPI_FILLED_VWAP_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_FILLED_VWAP_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_FILLED_VWAP_SIZE        8

static unsigned
parse_coinbasederivatives_ordersapi_filled_vwap(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_filled_vwap, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_FILLED_VWAP_SIZE, COINBASEDERIVATIVES_ORDERSAPI_FILLED_VWAP_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_FILLED_VWAP_SIZE;
}

/* Filled Vwap V13 */
#define COINBASEDERIVATIVES_ORDERSAPI_FILLED_VWAP_V13_NAME        "Filled Vwap"
#define COINBASEDERIVATIVES_ORDERSAPI_FILLED_VWAP_V13_DESCRIPTION "filledVwap"
#define COINBASEDERIVATIVES_ORDERSAPI_FILLED_VWAP_V13_FILTER      "coinbasederivatives.ordersapi.filledvwap"
#define COINBASEDERIVATIVES_ORDERSAPI_FILLED_VWAP_V13_TYPE        FT_INT64
#define COINBASEDERIVATIVES_ORDERSAPI_FILLED_VWAP_V13_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_FILLED_VWAP_V13_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_FILLED_VWAP_V13_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_FILLED_VWAP_V13_SIZE        8

static unsigned
parse_coinbasederivatives_ordersapi_filled_vwap_v13(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_filled_vwap_v13, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_FILLED_VWAP_V13_SIZE, COINBASEDERIVATIVES_ORDERSAPI_FILLED_VWAP_V13_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_FILLED_VWAP_V13_SIZE;
}

/* From Sequence Number */
#define COINBASEDERIVATIVES_ORDERSAPI_FROM_SEQUENCE_NUMBER_NAME        "From Sequence Number"
#define COINBASEDERIVATIVES_ORDERSAPI_FROM_SEQUENCE_NUMBER_DESCRIPTION "fromSequenceNumber"
#define COINBASEDERIVATIVES_ORDERSAPI_FROM_SEQUENCE_NUMBER_FILTER      "coinbasederivatives.ordersapi.fromsequencenumber"
#define COINBASEDERIVATIVES_ORDERSAPI_FROM_SEQUENCE_NUMBER_TYPE        FT_UINT32
#define COINBASEDERIVATIVES_ORDERSAPI_FROM_SEQUENCE_NUMBER_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_FROM_SEQUENCE_NUMBER_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_FROM_SEQUENCE_NUMBER_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_FROM_SEQUENCE_NUMBER_SIZE        4

static unsigned
parse_coinbasederivatives_ordersapi_from_sequence_number(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_from_sequence_number, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_FROM_SEQUENCE_NUMBER_SIZE, COINBASEDERIVATIVES_ORDERSAPI_FROM_SEQUENCE_NUMBER_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_FROM_SEQUENCE_NUMBER_SIZE;
}

/* Gap Fill Padding */
#define COINBASEDERIVATIVES_ORDERSAPI_GAP_FILL_PADDING_NAME        "Gap Fill Padding"
#define COINBASEDERIVATIVES_ORDERSAPI_GAP_FILL_PADDING_DESCRIPTION "padding"
#define COINBASEDERIVATIVES_ORDERSAPI_GAP_FILL_PADDING_FILTER      "coinbasederivatives.ordersapi.gapfillpadding"
#define COINBASEDERIVATIVES_ORDERSAPI_GAP_FILL_PADDING_TYPE        FT_UINT32
#define COINBASEDERIVATIVES_ORDERSAPI_GAP_FILL_PADDING_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_GAP_FILL_PADDING_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_GAP_FILL_PADDING_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_GAP_FILL_PADDING_SIZE        4

static unsigned
parse_coinbasederivatives_ordersapi_gap_fill_padding(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_gap_fill_padding, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_GAP_FILL_PADDING_SIZE, COINBASEDERIVATIVES_ORDERSAPI_GAP_FILL_PADDING_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_GAP_FILL_PADDING_SIZE;
}

/* Good Til Date */
#define COINBASEDERIVATIVES_ORDERSAPI_GOOD_TIL_DATE_NAME        "Good Til Date"
#define COINBASEDERIVATIVES_ORDERSAPI_GOOD_TIL_DATE_DESCRIPTION "goodTilDate"
#define COINBASEDERIVATIVES_ORDERSAPI_GOOD_TIL_DATE_FILTER      "coinbasederivatives.ordersapi.goodtildate"
#define COINBASEDERIVATIVES_ORDERSAPI_GOOD_TIL_DATE_TYPE        FT_UINT16
#define COINBASEDERIVATIVES_ORDERSAPI_GOOD_TIL_DATE_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_ORDERSAPI_GOOD_TIL_DATE_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_GOOD_TIL_DATE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_GOOD_TIL_DATE_SIZE        2

static unsigned
parse_coinbasederivatives_ordersapi_good_til_date(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_good_til_date, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_GOOD_TIL_DATE_SIZE, COINBASEDERIVATIVES_ORDERSAPI_GOOD_TIL_DATE_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_GOOD_TIL_DATE_SIZE;
}

/* Heartbeat Interval Seconds */
#define COINBASEDERIVATIVES_ORDERSAPI_HEARTBEAT_INTERVAL_SECONDS_NAME        "Heartbeat Interval Seconds"
#define COINBASEDERIVATIVES_ORDERSAPI_HEARTBEAT_INTERVAL_SECONDS_DESCRIPTION "heartbeatIntervalSeconds"
#define COINBASEDERIVATIVES_ORDERSAPI_HEARTBEAT_INTERVAL_SECONDS_FILTER      "coinbasederivatives.ordersapi.heartbeatintervalseconds"
#define COINBASEDERIVATIVES_ORDERSAPI_HEARTBEAT_INTERVAL_SECONDS_TYPE        FT_INT32
#define COINBASEDERIVATIVES_ORDERSAPI_HEARTBEAT_INTERVAL_SECONDS_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_HEARTBEAT_INTERVAL_SECONDS_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_HEARTBEAT_INTERVAL_SECONDS_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_HEARTBEAT_INTERVAL_SECONDS_SIZE        4

static unsigned
parse_coinbasederivatives_ordersapi_heartbeat_interval_seconds(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_heartbeat_interval_seconds, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_HEARTBEAT_INTERVAL_SECONDS_SIZE, COINBASEDERIVATIVES_ORDERSAPI_HEARTBEAT_INTERVAL_SECONDS_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_HEARTBEAT_INTERVAL_SECONDS_SIZE;
}

/* Instrument Id */
#define COINBASEDERIVATIVES_ORDERSAPI_INSTRUMENT_ID_NAME        "Instrument Id"
#define COINBASEDERIVATIVES_ORDERSAPI_INSTRUMENT_ID_DESCRIPTION "instrumentId"
#define COINBASEDERIVATIVES_ORDERSAPI_INSTRUMENT_ID_FILTER      "coinbasederivatives.ordersapi.instrumentid"
#define COINBASEDERIVATIVES_ORDERSAPI_INSTRUMENT_ID_TYPE        FT_INT32
#define COINBASEDERIVATIVES_ORDERSAPI_INSTRUMENT_ID_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_INSTRUMENT_ID_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_INSTRUMENT_ID_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_INSTRUMENT_ID_SIZE        4

static unsigned
parse_coinbasederivatives_ordersapi_instrument_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_instrument_id, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_INSTRUMENT_ID_SIZE, COINBASEDERIVATIVES_ORDERSAPI_INSTRUMENT_ID_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_INSTRUMENT_ID_SIZE;
}

/* Instrument Status */
#define COINBASEDERIVATIVES_ORDERSAPI_INSTRUMENT_STATUS_NAME        "Instrument Status"
#define COINBASEDERIVATIVES_ORDERSAPI_INSTRUMENT_STATUS_DESCRIPTION "status"
#define COINBASEDERIVATIVES_ORDERSAPI_INSTRUMENT_STATUS_FILTER      "coinbasederivatives.ordersapi.instrumentstatus"
#define COINBASEDERIVATIVES_ORDERSAPI_INSTRUMENT_STATUS_TYPE        FT_UINT8
#define COINBASEDERIVATIVES_ORDERSAPI_INSTRUMENT_STATUS_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_INSTRUMENT_STATUS_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_INSTRUMENT_STATUS_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_INSTRUMENT_STATUS_SIZE        1

static const value_string coinbasederivatives_ordersapi_instrument_status_vals[] = {
    { 1, "Pre Open" },
    { 2, "Pre Open No Cancel" },
    { 3, "Ready To Trade" },
    { 4, "Trading Halt" },
    { 5, "Close" },
    { 6, "Post Close" },
    { 0, NULL }
};

static unsigned
parse_coinbasederivatives_ordersapi_instrument_status(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_instrument_status, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_INSTRUMENT_STATUS_SIZE, COINBASEDERIVATIVES_ORDERSAPI_INSTRUMENT_STATUS_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_INSTRUMENT_STATUS_SIZE;
}

/* Is Aggressor */
#define COINBASEDERIVATIVES_ORDERSAPI_IS_AGGRESSOR_NAME        "Is Aggressor"
#define COINBASEDERIVATIVES_ORDERSAPI_IS_AGGRESSOR_DESCRIPTION "isAggressor"
#define COINBASEDERIVATIVES_ORDERSAPI_IS_AGGRESSOR_FILTER      "coinbasederivatives.ordersapi.isaggressor"
#define COINBASEDERIVATIVES_ORDERSAPI_IS_AGGRESSOR_TYPE        FT_INT8
#define COINBASEDERIVATIVES_ORDERSAPI_IS_AGGRESSOR_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_IS_AGGRESSOR_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_IS_AGGRESSOR_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_IS_AGGRESSOR_SIZE        1

static const value_string coinbasederivatives_ordersapi_is_aggressor_vals[] = {
    { 0, "False" },
    { 1, "True" },
    { 0, NULL }
};

static unsigned
parse_coinbasederivatives_ordersapi_is_aggressor(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_is_aggressor, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_IS_AGGRESSOR_SIZE, COINBASEDERIVATIVES_ORDERSAPI_IS_AGGRESSOR_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_IS_AGGRESSOR_SIZE;
}

/* Is Last Message */
#define COINBASEDERIVATIVES_ORDERSAPI_IS_LAST_MESSAGE_NAME        "Is Last Message"
#define COINBASEDERIVATIVES_ORDERSAPI_IS_LAST_MESSAGE_DESCRIPTION "isLastMessage"
#define COINBASEDERIVATIVES_ORDERSAPI_IS_LAST_MESSAGE_FILTER      "coinbasederivatives.ordersapi.islastmessage"
#define COINBASEDERIVATIVES_ORDERSAPI_IS_LAST_MESSAGE_TYPE        FT_INT8
#define COINBASEDERIVATIVES_ORDERSAPI_IS_LAST_MESSAGE_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_IS_LAST_MESSAGE_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_IS_LAST_MESSAGE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_IS_LAST_MESSAGE_SIZE        1

static const value_string coinbasederivatives_ordersapi_is_last_message_vals[] = {
    { 0, "False" },
    { 1, "True" },
    { 0, NULL }
};

static unsigned
parse_coinbasederivatives_ordersapi_is_last_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_is_last_message, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_IS_LAST_MESSAGE_SIZE, COINBASEDERIVATIVES_ORDERSAPI_IS_LAST_MESSAGE_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_IS_LAST_MESSAGE_SIZE;
}

/* Is Resend */
#define COINBASEDERIVATIVES_ORDERSAPI_IS_RESEND_NAME        "Is Resend"
#define COINBASEDERIVATIVES_ORDERSAPI_IS_RESEND_DESCRIPTION "Possibly resent message indicator (Bit 0)"
#define COINBASEDERIVATIVES_ORDERSAPI_IS_RESEND_FILTER      "coinbasederivatives.ordersapi.isresend"
#define COINBASEDERIVATIVES_ORDERSAPI_IS_RESEND_TYPE        FT_BOOLEAN
#define COINBASEDERIVATIVES_ORDERSAPI_IS_RESEND_DISPLAY     8
#define COINBASEDERIVATIVES_ORDERSAPI_IS_RESEND_MASK        0x01

/* Last Exec Id */
#define COINBASEDERIVATIVES_ORDERSAPI_LAST_EXEC_ID_NAME        "Last Exec Id"
#define COINBASEDERIVATIVES_ORDERSAPI_LAST_EXEC_ID_DESCRIPTION "lastExecId"
#define COINBASEDERIVATIVES_ORDERSAPI_LAST_EXEC_ID_FILTER      "coinbasederivatives.ordersapi.lastexecid"
#define COINBASEDERIVATIVES_ORDERSAPI_LAST_EXEC_ID_TYPE        FT_INT64
#define COINBASEDERIVATIVES_ORDERSAPI_LAST_EXEC_ID_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_LAST_EXEC_ID_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_LAST_EXEC_ID_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_LAST_EXEC_ID_SIZE        8

static unsigned
parse_coinbasederivatives_ordersapi_last_exec_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_last_exec_id, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_LAST_EXEC_ID_SIZE, COINBASEDERIVATIVES_ORDERSAPI_LAST_EXEC_ID_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_LAST_EXEC_ID_SIZE;
}

/* Last Processed Fill Id */
#define COINBASEDERIVATIVES_ORDERSAPI_LAST_PROCESSED_FILL_ID_NAME        "Last Processed Fill Id"
#define COINBASEDERIVATIVES_ORDERSAPI_LAST_PROCESSED_FILL_ID_DESCRIPTION "lastProcessedFillId"
#define COINBASEDERIVATIVES_ORDERSAPI_LAST_PROCESSED_FILL_ID_FILTER      "coinbasederivatives.ordersapi.lastprocessedfillid"
#define COINBASEDERIVATIVES_ORDERSAPI_LAST_PROCESSED_FILL_ID_TYPE        FT_INT64
#define COINBASEDERIVATIVES_ORDERSAPI_LAST_PROCESSED_FILL_ID_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_ORDERSAPI_LAST_PROCESSED_FILL_ID_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_LAST_PROCESSED_FILL_ID_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_LAST_PROCESSED_FILL_ID_SIZE        8

static unsigned
parse_coinbasederivatives_ordersapi_last_processed_fill_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_last_processed_fill_id, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_LAST_PROCESSED_FILL_ID_SIZE, COINBASEDERIVATIVES_ORDERSAPI_LAST_PROCESSED_FILL_ID_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_LAST_PROCESSED_FILL_ID_SIZE;
}

/* Last Processed Seq No */
#define COINBASEDERIVATIVES_ORDERSAPI_LAST_PROCESSED_SEQ_NO_NAME        "Last Processed Seq No"
#define COINBASEDERIVATIVES_ORDERSAPI_LAST_PROCESSED_SEQ_NO_DESCRIPTION "Highest sequence number the sender has processed from the counterparty"
#define COINBASEDERIVATIVES_ORDERSAPI_LAST_PROCESSED_SEQ_NO_FILTER      "coinbasederivatives.ordersapi.lastprocessedseqno"
#define COINBASEDERIVATIVES_ORDERSAPI_LAST_PROCESSED_SEQ_NO_TYPE        FT_UINT32
#define COINBASEDERIVATIVES_ORDERSAPI_LAST_PROCESSED_SEQ_NO_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_LAST_PROCESSED_SEQ_NO_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_LAST_PROCESSED_SEQ_NO_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_LAST_PROCESSED_SEQ_NO_SIZE        4

static unsigned
parse_coinbasederivatives_ordersapi_last_processed_seq_no(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_last_processed_seq_no, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_LAST_PROCESSED_SEQ_NO_SIZE, COINBASEDERIVATIVES_ORDERSAPI_LAST_PROCESSED_SEQ_NO_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_LAST_PROCESSED_SEQ_NO_SIZE;
}

/* Leg 1 Fill Price */
#define COINBASEDERIVATIVES_ORDERSAPI_LEG_1_FILL_PRICE_NAME        "Leg 1 Fill Price"
#define COINBASEDERIVATIVES_ORDERSAPI_LEG_1_FILL_PRICE_DESCRIPTION "leg1FillPrice"
#define COINBASEDERIVATIVES_ORDERSAPI_LEG_1_FILL_PRICE_FILTER      "coinbasederivatives.ordersapi.leg1fillprice"
#define COINBASEDERIVATIVES_ORDERSAPI_LEG_1_FILL_PRICE_TYPE        FT_INT64
#define COINBASEDERIVATIVES_ORDERSAPI_LEG_1_FILL_PRICE_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_ORDERSAPI_LEG_1_FILL_PRICE_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_LEG_1_FILL_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_LEG_1_FILL_PRICE_SIZE        8

static unsigned
parse_coinbasederivatives_ordersapi_leg_1_fill_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_leg_1_fill_price, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_LEG_1_FILL_PRICE_SIZE, COINBASEDERIVATIVES_ORDERSAPI_LEG_1_FILL_PRICE_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_LEG_1_FILL_PRICE_SIZE;
}

/* Leg 1 Fill Price V13 */
#define COINBASEDERIVATIVES_ORDERSAPI_LEG_1_FILL_PRICE_V13_NAME        "Leg 1 Fill Price"
#define COINBASEDERIVATIVES_ORDERSAPI_LEG_1_FILL_PRICE_V13_DESCRIPTION "leg1FillPrice"
#define COINBASEDERIVATIVES_ORDERSAPI_LEG_1_FILL_PRICE_V13_FILTER      "coinbasederivatives.ordersapi.leg1fillprice"
#define COINBASEDERIVATIVES_ORDERSAPI_LEG_1_FILL_PRICE_V13_TYPE        FT_INT64
#define COINBASEDERIVATIVES_ORDERSAPI_LEG_1_FILL_PRICE_V13_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_LEG_1_FILL_PRICE_V13_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_LEG_1_FILL_PRICE_V13_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_LEG_1_FILL_PRICE_V13_SIZE        8

static unsigned
parse_coinbasederivatives_ordersapi_leg_1_fill_price_v13(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_leg_1_fill_price_v13, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_LEG_1_FILL_PRICE_V13_SIZE, COINBASEDERIVATIVES_ORDERSAPI_LEG_1_FILL_PRICE_V13_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_LEG_1_FILL_PRICE_V13_SIZE;
}

/* Leg 2 Fill Price */
#define COINBASEDERIVATIVES_ORDERSAPI_LEG_2_FILL_PRICE_NAME        "Leg 2 Fill Price"
#define COINBASEDERIVATIVES_ORDERSAPI_LEG_2_FILL_PRICE_DESCRIPTION "leg2FillPrice"
#define COINBASEDERIVATIVES_ORDERSAPI_LEG_2_FILL_PRICE_FILTER      "coinbasederivatives.ordersapi.leg2fillprice"
#define COINBASEDERIVATIVES_ORDERSAPI_LEG_2_FILL_PRICE_TYPE        FT_INT64
#define COINBASEDERIVATIVES_ORDERSAPI_LEG_2_FILL_PRICE_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_ORDERSAPI_LEG_2_FILL_PRICE_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_LEG_2_FILL_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_LEG_2_FILL_PRICE_SIZE        8

static unsigned
parse_coinbasederivatives_ordersapi_leg_2_fill_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_leg_2_fill_price, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_LEG_2_FILL_PRICE_SIZE, COINBASEDERIVATIVES_ORDERSAPI_LEG_2_FILL_PRICE_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_LEG_2_FILL_PRICE_SIZE;
}

/* Leg 2 Fill Price V13 */
#define COINBASEDERIVATIVES_ORDERSAPI_LEG_2_FILL_PRICE_V13_NAME        "Leg 2 Fill Price"
#define COINBASEDERIVATIVES_ORDERSAPI_LEG_2_FILL_PRICE_V13_DESCRIPTION "leg2FillPrice"
#define COINBASEDERIVATIVES_ORDERSAPI_LEG_2_FILL_PRICE_V13_FILTER      "coinbasederivatives.ordersapi.leg2fillprice"
#define COINBASEDERIVATIVES_ORDERSAPI_LEG_2_FILL_PRICE_V13_TYPE        FT_INT64
#define COINBASEDERIVATIVES_ORDERSAPI_LEG_2_FILL_PRICE_V13_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_LEG_2_FILL_PRICE_V13_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_LEG_2_FILL_PRICE_V13_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_LEG_2_FILL_PRICE_V13_SIZE        8

static unsigned
parse_coinbasederivatives_ordersapi_leg_2_fill_price_v13(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_leg_2_fill_price_v13, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_LEG_2_FILL_PRICE_V13_SIZE, COINBASEDERIVATIVES_ORDERSAPI_LEG_2_FILL_PRICE_V13_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_LEG_2_FILL_PRICE_V13_SIZE;
}

/* Limit Price */
#define COINBASEDERIVATIVES_ORDERSAPI_LIMIT_PRICE_NAME        "Limit Price"
#define COINBASEDERIVATIVES_ORDERSAPI_LIMIT_PRICE_DESCRIPTION "limitPrice"
#define COINBASEDERIVATIVES_ORDERSAPI_LIMIT_PRICE_FILTER      "coinbasederivatives.ordersapi.limitprice"
#define COINBASEDERIVATIVES_ORDERSAPI_LIMIT_PRICE_TYPE        FT_INT64
#define COINBASEDERIVATIVES_ORDERSAPI_LIMIT_PRICE_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_ORDERSAPI_LIMIT_PRICE_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_LIMIT_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_LIMIT_PRICE_SIZE        8

static unsigned
parse_coinbasederivatives_ordersapi_limit_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_limit_price, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_LIMIT_PRICE_SIZE, COINBASEDERIVATIVES_ORDERSAPI_LIMIT_PRICE_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_LIMIT_PRICE_SIZE;
}

/* Limit Price V13 */
#define COINBASEDERIVATIVES_ORDERSAPI_LIMIT_PRICE_V13_NAME        "Limit Price"
#define COINBASEDERIVATIVES_ORDERSAPI_LIMIT_PRICE_V13_DESCRIPTION "limitPrice"
#define COINBASEDERIVATIVES_ORDERSAPI_LIMIT_PRICE_V13_FILTER      "coinbasederivatives.ordersapi.limitprice"
#define COINBASEDERIVATIVES_ORDERSAPI_LIMIT_PRICE_V13_TYPE        FT_INT64
#define COINBASEDERIVATIVES_ORDERSAPI_LIMIT_PRICE_V13_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_LIMIT_PRICE_V13_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_LIMIT_PRICE_V13_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_LIMIT_PRICE_V13_SIZE        8

static unsigned
parse_coinbasederivatives_ordersapi_limit_price_v13(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_limit_price_v13, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_LIMIT_PRICE_V13_SIZE, COINBASEDERIVATIVES_ORDERSAPI_LIMIT_PRICE_V13_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_LIMIT_PRICE_V13_SIZE;
}

/* Match Id */
#define COINBASEDERIVATIVES_ORDERSAPI_MATCH_ID_NAME        "Match Id"
#define COINBASEDERIVATIVES_ORDERSAPI_MATCH_ID_DESCRIPTION "matchId"
#define COINBASEDERIVATIVES_ORDERSAPI_MATCH_ID_FILTER      "coinbasederivatives.ordersapi.matchid"
#define COINBASEDERIVATIVES_ORDERSAPI_MATCH_ID_TYPE        FT_INT64
#define COINBASEDERIVATIVES_ORDERSAPI_MATCH_ID_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_MATCH_ID_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_MATCH_ID_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_MATCH_ID_SIZE        8

static unsigned
parse_coinbasederivatives_ordersapi_match_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_match_id, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_MATCH_ID_SIZE, COINBASEDERIVATIVES_ORDERSAPI_MATCH_ID_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_MATCH_ID_SIZE;
}

/* Message Length */
#define COINBASEDERIVATIVES_ORDERSAPI_MESSAGE_LENGTH_NAME        "Message Length"
#define COINBASEDERIVATIVES_ORDERSAPI_MESSAGE_LENGTH_DESCRIPTION "Total message length in bytes including this header"
#define COINBASEDERIVATIVES_ORDERSAPI_MESSAGE_LENGTH_FILTER      "coinbasederivatives.ordersapi.messagelength"
#define COINBASEDERIVATIVES_ORDERSAPI_MESSAGE_LENGTH_TYPE        FT_UINT16
#define COINBASEDERIVATIVES_ORDERSAPI_MESSAGE_LENGTH_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_MESSAGE_LENGTH_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_MESSAGE_LENGTH_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_MESSAGE_LENGTH_SIZE        2

static unsigned
parse_coinbasederivatives_ordersapi_message_length(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_message_length, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_MESSAGE_LENGTH_SIZE, COINBASEDERIVATIVES_ORDERSAPI_MESSAGE_LENGTH_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_MESSAGE_LENGTH_SIZE;
}

/* Min Qty */
#define COINBASEDERIVATIVES_ORDERSAPI_MIN_QTY_NAME        "Min Qty"
#define COINBASEDERIVATIVES_ORDERSAPI_MIN_QTY_DESCRIPTION "minQty"
#define COINBASEDERIVATIVES_ORDERSAPI_MIN_QTY_FILTER      "coinbasederivatives.ordersapi.minqty"
#define COINBASEDERIVATIVES_ORDERSAPI_MIN_QTY_TYPE        FT_INT32
#define COINBASEDERIVATIVES_ORDERSAPI_MIN_QTY_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_ORDERSAPI_MIN_QTY_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_MIN_QTY_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_MIN_QTY_SIZE        4

static unsigned
parse_coinbasederivatives_ordersapi_min_qty(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_min_qty, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_MIN_QTY_SIZE, COINBASEDERIVATIVES_ORDERSAPI_MIN_QTY_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_MIN_QTY_SIZE;
}

/* New Limit Price */
#define COINBASEDERIVATIVES_ORDERSAPI_NEW_LIMIT_PRICE_NAME        "New Limit Price"
#define COINBASEDERIVATIVES_ORDERSAPI_NEW_LIMIT_PRICE_DESCRIPTION "newLimitPrice"
#define COINBASEDERIVATIVES_ORDERSAPI_NEW_LIMIT_PRICE_FILTER      "coinbasederivatives.ordersapi.newlimitprice"
#define COINBASEDERIVATIVES_ORDERSAPI_NEW_LIMIT_PRICE_TYPE        FT_INT64
#define COINBASEDERIVATIVES_ORDERSAPI_NEW_LIMIT_PRICE_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_ORDERSAPI_NEW_LIMIT_PRICE_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_NEW_LIMIT_PRICE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_NEW_LIMIT_PRICE_SIZE        8

static unsigned
parse_coinbasederivatives_ordersapi_new_limit_price(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_new_limit_price, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_NEW_LIMIT_PRICE_SIZE, COINBASEDERIVATIVES_ORDERSAPI_NEW_LIMIT_PRICE_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_NEW_LIMIT_PRICE_SIZE;
}

/* New Limit Price V13 */
#define COINBASEDERIVATIVES_ORDERSAPI_NEW_LIMIT_PRICE_V13_NAME        "New Limit Price"
#define COINBASEDERIVATIVES_ORDERSAPI_NEW_LIMIT_PRICE_V13_DESCRIPTION "newLimitPrice"
#define COINBASEDERIVATIVES_ORDERSAPI_NEW_LIMIT_PRICE_V13_FILTER      "coinbasederivatives.ordersapi.newlimitprice"
#define COINBASEDERIVATIVES_ORDERSAPI_NEW_LIMIT_PRICE_V13_TYPE        FT_INT64
#define COINBASEDERIVATIVES_ORDERSAPI_NEW_LIMIT_PRICE_V13_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_ORDERSAPI_NEW_LIMIT_PRICE_V13_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_NEW_LIMIT_PRICE_V13_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_NEW_LIMIT_PRICE_V13_SIZE        8

static unsigned
parse_coinbasederivatives_ordersapi_new_limit_price_v13(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_new_limit_price_v13, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_NEW_LIMIT_PRICE_V13_SIZE, COINBASEDERIVATIVES_ORDERSAPI_NEW_LIMIT_PRICE_V13_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_NEW_LIMIT_PRICE_V13_SIZE;
}

/* New Quantity */
#define COINBASEDERIVATIVES_ORDERSAPI_NEW_QUANTITY_NAME        "New Quantity"
#define COINBASEDERIVATIVES_ORDERSAPI_NEW_QUANTITY_DESCRIPTION "newQuantity"
#define COINBASEDERIVATIVES_ORDERSAPI_NEW_QUANTITY_FILTER      "coinbasederivatives.ordersapi.newquantity"
#define COINBASEDERIVATIVES_ORDERSAPI_NEW_QUANTITY_TYPE        FT_INT32
#define COINBASEDERIVATIVES_ORDERSAPI_NEW_QUANTITY_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_ORDERSAPI_NEW_QUANTITY_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_NEW_QUANTITY_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_NEW_QUANTITY_SIZE        4

static unsigned
parse_coinbasederivatives_ordersapi_new_quantity(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_new_quantity, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_NEW_QUANTITY_SIZE, COINBASEDERIVATIVES_ORDERSAPI_NEW_QUANTITY_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_NEW_QUANTITY_SIZE;
}

/* New Sequence Number */
#define COINBASEDERIVATIVES_ORDERSAPI_NEW_SEQUENCE_NUMBER_NAME        "New Sequence Number"
#define COINBASEDERIVATIVES_ORDERSAPI_NEW_SEQUENCE_NUMBER_DESCRIPTION "newSequenceNumber"
#define COINBASEDERIVATIVES_ORDERSAPI_NEW_SEQUENCE_NUMBER_FILTER      "coinbasederivatives.ordersapi.newsequencenumber"
#define COINBASEDERIVATIVES_ORDERSAPI_NEW_SEQUENCE_NUMBER_TYPE        FT_UINT32
#define COINBASEDERIVATIVES_ORDERSAPI_NEW_SEQUENCE_NUMBER_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_NEW_SEQUENCE_NUMBER_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_NEW_SEQUENCE_NUMBER_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_NEW_SEQUENCE_NUMBER_SIZE        4

static unsigned
parse_coinbasederivatives_ordersapi_new_sequence_number(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_new_sequence_number, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_NEW_SEQUENCE_NUMBER_SIZE, COINBASEDERIVATIVES_ORDERSAPI_NEW_SEQUENCE_NUMBER_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_NEW_SEQUENCE_NUMBER_SIZE;
}

/* Num Users Affected */
#define COINBASEDERIVATIVES_ORDERSAPI_NUM_USERS_AFFECTED_NAME        "Num Users Affected"
#define COINBASEDERIVATIVES_ORDERSAPI_NUM_USERS_AFFECTED_DESCRIPTION "numUsersAffected"
#define COINBASEDERIVATIVES_ORDERSAPI_NUM_USERS_AFFECTED_FILTER      "coinbasederivatives.ordersapi.numusersaffected"
#define COINBASEDERIVATIVES_ORDERSAPI_NUM_USERS_AFFECTED_TYPE        FT_INT32
#define COINBASEDERIVATIVES_ORDERSAPI_NUM_USERS_AFFECTED_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_NUM_USERS_AFFECTED_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_NUM_USERS_AFFECTED_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_NUM_USERS_AFFECTED_SIZE        4

static unsigned
parse_coinbasederivatives_ordersapi_num_users_affected(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_num_users_affected, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_NUM_USERS_AFFECTED_SIZE, COINBASEDERIVATIVES_ORDERSAPI_NUM_USERS_AFFECTED_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_NUM_USERS_AFFECTED_SIZE;
}

/* Only Current Session */
#define COINBASEDERIVATIVES_ORDERSAPI_ONLY_CURRENT_SESSION_NAME        "Only Current Session"
#define COINBASEDERIVATIVES_ORDERSAPI_ONLY_CURRENT_SESSION_DESCRIPTION "onlyCurrentSession"
#define COINBASEDERIVATIVES_ORDERSAPI_ONLY_CURRENT_SESSION_FILTER      "coinbasederivatives.ordersapi.onlycurrentsession"
#define COINBASEDERIVATIVES_ORDERSAPI_ONLY_CURRENT_SESSION_TYPE        FT_INT8
#define COINBASEDERIVATIVES_ORDERSAPI_ONLY_CURRENT_SESSION_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_ONLY_CURRENT_SESSION_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_ONLY_CURRENT_SESSION_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_ONLY_CURRENT_SESSION_SIZE        1

static const value_string coinbasederivatives_ordersapi_only_current_session_vals[] = {
    { 0, "False" },
    { 1, "True" },
    { 0, NULL }
};

static unsigned
parse_coinbasederivatives_ordersapi_only_current_session(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_only_current_session, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_ONLY_CURRENT_SESSION_SIZE, COINBASEDERIVATIVES_ORDERSAPI_ONLY_CURRENT_SESSION_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_ONLY_CURRENT_SESSION_SIZE;
}

/* Order Id */
#define COINBASEDERIVATIVES_ORDERSAPI_ORDER_ID_NAME        "Order Id"
#define COINBASEDERIVATIVES_ORDERSAPI_ORDER_ID_DESCRIPTION "orderId"
#define COINBASEDERIVATIVES_ORDERSAPI_ORDER_ID_FILTER      "coinbasederivatives.ordersapi.orderid"
#define COINBASEDERIVATIVES_ORDERSAPI_ORDER_ID_TYPE        FT_INT64
#define COINBASEDERIVATIVES_ORDERSAPI_ORDER_ID_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_ORDER_ID_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_ORDER_ID_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_ORDER_ID_SIZE        8

static unsigned
parse_coinbasederivatives_ordersapi_order_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_order_id, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_ORDER_ID_SIZE, COINBASEDERIVATIVES_ORDERSAPI_ORDER_ID_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_ORDER_ID_SIZE;
}

/* Order Id Optional */
#define COINBASEDERIVATIVES_ORDERSAPI_ORDER_ID_OPTIONAL_NAME        "Order Id Optional"
#define COINBASEDERIVATIVES_ORDERSAPI_ORDER_ID_OPTIONAL_DESCRIPTION "orderId"
#define COINBASEDERIVATIVES_ORDERSAPI_ORDER_ID_OPTIONAL_FILTER      "coinbasederivatives.ordersapi.orderidoptional"
#define COINBASEDERIVATIVES_ORDERSAPI_ORDER_ID_OPTIONAL_TYPE        FT_INT64
#define COINBASEDERIVATIVES_ORDERSAPI_ORDER_ID_OPTIONAL_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_ORDERSAPI_ORDER_ID_OPTIONAL_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_ORDER_ID_OPTIONAL_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_ORDER_ID_OPTIONAL_SIZE        8

static unsigned
parse_coinbasederivatives_ordersapi_order_id_optional(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_order_id_optional, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_ORDER_ID_OPTIONAL_SIZE, COINBASEDERIVATIVES_ORDERSAPI_ORDER_ID_OPTIONAL_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_ORDER_ID_OPTIONAL_SIZE;
}

/* Order Reject Details */
#define COINBASEDERIVATIVES_ORDERSAPI_ORDER_REJECT_DETAILS_NAME        "Order Reject Details"
#define COINBASEDERIVATIVES_ORDERSAPI_ORDER_REJECT_DETAILS_DESCRIPTION "details"
#define COINBASEDERIVATIVES_ORDERSAPI_ORDER_REJECT_DETAILS_FILTER      "coinbasederivatives.ordersapi.orderrejectdetails"
#define COINBASEDERIVATIVES_ORDERSAPI_ORDER_REJECT_DETAILS_TYPE        FT_STRING
#define COINBASEDERIVATIVES_ORDERSAPI_ORDER_REJECT_DETAILS_DISPLAY     BASE_NONE
#define COINBASEDERIVATIVES_ORDERSAPI_ORDER_REJECT_DETAILS_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_ORDER_REJECT_DETAILS_ENCODING    ENC_ASCII
#define COINBASEDERIVATIVES_ORDERSAPI_ORDER_REJECT_DETAILS_SIZE        47

static unsigned
parse_coinbasederivatives_ordersapi_order_reject_details(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_order_reject_details, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_ORDER_REJECT_DETAILS_SIZE, COINBASEDERIVATIVES_ORDERSAPI_ORDER_REJECT_DETAILS_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_ORDER_REJECT_DETAILS_SIZE;
}

/* Order Reject Reason */
#define COINBASEDERIVATIVES_ORDERSAPI_ORDER_REJECT_REASON_NAME        "Order Reject Reason"
#define COINBASEDERIVATIVES_ORDERSAPI_ORDER_REJECT_REASON_DESCRIPTION "rejectReason"
#define COINBASEDERIVATIVES_ORDERSAPI_ORDER_REJECT_REASON_FILTER      "coinbasederivatives.ordersapi.orderrejectreason"
#define COINBASEDERIVATIVES_ORDERSAPI_ORDER_REJECT_REASON_TYPE        FT_UINT8
#define COINBASEDERIVATIVES_ORDERSAPI_ORDER_REJECT_REASON_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_ORDER_REJECT_REASON_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_ORDER_REJECT_REASON_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_ORDER_REJECT_REASON_SIZE        1

static const value_string coinbasederivatives_ordersapi_order_reject_reason_vals[] = {
    { 1, "Error" },
    { 2, "Invalid Instrument" },
    { 3, "Cl Ord Id In Use" },
    { 8, "Validation Failure" },
    { 9, "Unknown Order" },
    { 0, NULL }
};

static unsigned
parse_coinbasederivatives_ordersapi_order_reject_reason(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_order_reject_reason, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_ORDER_REJECT_REASON_SIZE, COINBASEDERIVATIVES_ORDERSAPI_ORDER_REJECT_REASON_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_ORDER_REJECT_REASON_SIZE;
}

/* Padding */
#define COINBASEDERIVATIVES_ORDERSAPI_PADDING_NAME        "Padding"
#define COINBASEDERIVATIVES_ORDERSAPI_PADDING_DESCRIPTION "Tcp sbe alignment padding"
#define COINBASEDERIVATIVES_ORDERSAPI_PADDING_FILTER      "coinbasederivatives.ordersapi.padding"
#define COINBASEDERIVATIVES_ORDERSAPI_PADDING_TYPE        FT_BYTES
#define COINBASEDERIVATIVES_ORDERSAPI_PADDING_DISPLAY     BASE_NONE
#define COINBASEDERIVATIVES_ORDERSAPI_PADDING_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_PADDING_ENCODING    ENC_NA

/* Password */
#define COINBASEDERIVATIVES_ORDERSAPI_PASSWORD_NAME        "Password"
#define COINBASEDERIVATIVES_ORDERSAPI_PASSWORD_DESCRIPTION "Logon password"
#define COINBASEDERIVATIVES_ORDERSAPI_PASSWORD_FILTER      "coinbasederivatives.ordersapi.password"
#define COINBASEDERIVATIVES_ORDERSAPI_PASSWORD_TYPE        FT_STRING
#define COINBASEDERIVATIVES_ORDERSAPI_PASSWORD_DISPLAY     BASE_NONE
#define COINBASEDERIVATIVES_ORDERSAPI_PASSWORD_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_PASSWORD_ENCODING    ENC_ASCII
#define COINBASEDERIVATIVES_ORDERSAPI_PASSWORD_SIZE        32

static unsigned
parse_coinbasederivatives_ordersapi_password(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_password, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_PASSWORD_SIZE, COINBASEDERIVATIVES_ORDERSAPI_PASSWORD_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_PASSWORD_SIZE;
}

/* Post Only */
#define COINBASEDERIVATIVES_ORDERSAPI_POST_ONLY_NAME        "Post Only"
#define COINBASEDERIVATIVES_ORDERSAPI_POST_ONLY_DESCRIPTION "postOnly"
#define COINBASEDERIVATIVES_ORDERSAPI_POST_ONLY_FILTER      "coinbasederivatives.ordersapi.postonly"
#define COINBASEDERIVATIVES_ORDERSAPI_POST_ONLY_TYPE        FT_BOOLEAN
#define COINBASEDERIVATIVES_ORDERSAPI_POST_ONLY_DISPLAY     8
#define COINBASEDERIVATIVES_ORDERSAPI_POST_ONLY_MASK        0x01

/* Product Id */
#define COINBASEDERIVATIVES_ORDERSAPI_PRODUCT_ID_NAME        "Product Id"
#define COINBASEDERIVATIVES_ORDERSAPI_PRODUCT_ID_DESCRIPTION "productId"
#define COINBASEDERIVATIVES_ORDERSAPI_PRODUCT_ID_FILTER      "coinbasederivatives.ordersapi.productid"
#define COINBASEDERIVATIVES_ORDERSAPI_PRODUCT_ID_TYPE        FT_INT32
#define COINBASEDERIVATIVES_ORDERSAPI_PRODUCT_ID_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_PRODUCT_ID_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_PRODUCT_ID_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_PRODUCT_ID_SIZE        4

static unsigned
parse_coinbasederivatives_ordersapi_product_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_product_id, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_PRODUCT_ID_SIZE, COINBASEDERIVATIVES_ORDERSAPI_PRODUCT_ID_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_PRODUCT_ID_SIZE;
}

/* Protocol Id */
#define COINBASEDERIVATIVES_ORDERSAPI_PROTOCOL_ID_NAME        "Protocol Id"
#define COINBASEDERIVATIVES_ORDERSAPI_PROTOCOL_ID_DESCRIPTION "Coinbase protocol identifier"
#define COINBASEDERIVATIVES_ORDERSAPI_PROTOCOL_ID_FILTER      "coinbasederivatives.ordersapi.protocolid"
#define COINBASEDERIVATIVES_ORDERSAPI_PROTOCOL_ID_TYPE        FT_UINT8
#define COINBASEDERIVATIVES_ORDERSAPI_PROTOCOL_ID_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_PROTOCOL_ID_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_PROTOCOL_ID_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_PROTOCOL_ID_SIZE        1

static unsigned
parse_coinbasederivatives_ordersapi_protocol_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_protocol_id, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_PROTOCOL_ID_SIZE, COINBASEDERIVATIVES_ORDERSAPI_PROTOCOL_ID_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_PROTOCOL_ID_SIZE;
}

/* Quantity */
#define COINBASEDERIVATIVES_ORDERSAPI_QUANTITY_NAME        "Quantity"
#define COINBASEDERIVATIVES_ORDERSAPI_QUANTITY_DESCRIPTION "Quantity with 0 decimal places"
#define COINBASEDERIVATIVES_ORDERSAPI_QUANTITY_FILTER      "coinbasederivatives.ordersapi.quantity"
#define COINBASEDERIVATIVES_ORDERSAPI_QUANTITY_TYPE        FT_INT32
#define COINBASEDERIVATIVES_ORDERSAPI_QUANTITY_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_QUANTITY_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_QUANTITY_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_QUANTITY_SIZE        4

static unsigned
parse_coinbasederivatives_ordersapi_quantity(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_quantity, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_QUANTITY_SIZE, COINBASEDERIVATIVES_ORDERSAPI_QUANTITY_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_QUANTITY_SIZE;
}

/* Reason */
#define COINBASEDERIVATIVES_ORDERSAPI_REASON_NAME     "Reason"
#define COINBASEDERIVATIVES_ORDERSAPI_REASON_FILTER   "coinbasederivatives.ordersapi.reason"
#define COINBASEDERIVATIVES_ORDERSAPI_REASON_TYPE     FT_STRING
#define COINBASEDERIVATIVES_ORDERSAPI_REASON_DISPLAY  BASE_NONE
#define COINBASEDERIVATIVES_ORDERSAPI_REASON_MASK     0x0
#define COINBASEDERIVATIVES_ORDERSAPI_REASON_ENCODING ENC_ASCII
#define COINBASEDERIVATIVES_ORDERSAPI_REASON_SIZE     64

static unsigned
parse_coinbasederivatives_ordersapi_reason(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_reason, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_REASON_SIZE, COINBASEDERIVATIVES_ORDERSAPI_REASON_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_REASON_SIZE;
}

/* Reason String 64 */
#define COINBASEDERIVATIVES_ORDERSAPI_REASON_STRING_64_NAME        "Reason String 64"
#define COINBASEDERIVATIVES_ORDERSAPI_REASON_STRING_64_DESCRIPTION "reason"
#define COINBASEDERIVATIVES_ORDERSAPI_REASON_STRING_64_FILTER      "coinbasederivatives.ordersapi.reasonstring64"
#define COINBASEDERIVATIVES_ORDERSAPI_REASON_STRING_64_TYPE        FT_STRING
#define COINBASEDERIVATIVES_ORDERSAPI_REASON_STRING_64_DISPLAY     BASE_NONE
#define COINBASEDERIVATIVES_ORDERSAPI_REASON_STRING_64_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_REASON_STRING_64_ENCODING    ENC_ASCII
#define COINBASEDERIVATIVES_ORDERSAPI_REASON_STRING_64_SIZE        64

static unsigned
parse_coinbasederivatives_ordersapi_reason_string_64(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_reason_string_64, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_REASON_STRING_64_SIZE, COINBASEDERIVATIVES_ORDERSAPI_REASON_STRING_64_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_REASON_STRING_64_SIZE;
}

/* Receive Time */
#define COINBASEDERIVATIVES_ORDERSAPI_RECEIVE_TIME_NAME        "Receive Time"
#define COINBASEDERIVATIVES_ORDERSAPI_RECEIVE_TIME_DESCRIPTION "receiveTime"
#define COINBASEDERIVATIVES_ORDERSAPI_RECEIVE_TIME_FILTER      "coinbasederivatives.ordersapi.receivetime"
#define COINBASEDERIVATIVES_ORDERSAPI_RECEIVE_TIME_TYPE        FT_ABSOLUTE_TIME
#define COINBASEDERIVATIVES_ORDERSAPI_RECEIVE_TIME_DISPLAY     ABSOLUTE_TIME_UTC
#define COINBASEDERIVATIVES_ORDERSAPI_RECEIVE_TIME_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_RECEIVE_TIME_ENCODING    ENC_TIME_NSECS | ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_RECEIVE_TIME_SIZE        8

static unsigned
parse_coinbasederivatives_ordersapi_receive_time(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_receive_time, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_RECEIVE_TIME_SIZE, COINBASEDERIVATIVES_ORDERSAPI_RECEIVE_TIME_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_RECEIVE_TIME_SIZE;
}

/* Ref Sequence Number */
#define COINBASEDERIVATIVES_ORDERSAPI_REF_SEQUENCE_NUMBER_NAME        "Ref Sequence Number"
#define COINBASEDERIVATIVES_ORDERSAPI_REF_SEQUENCE_NUMBER_DESCRIPTION "refSequenceNumber"
#define COINBASEDERIVATIVES_ORDERSAPI_REF_SEQUENCE_NUMBER_FILTER      "coinbasederivatives.ordersapi.refsequencenumber"
#define COINBASEDERIVATIVES_ORDERSAPI_REF_SEQUENCE_NUMBER_TYPE        FT_UINT32
#define COINBASEDERIVATIVES_ORDERSAPI_REF_SEQUENCE_NUMBER_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_REF_SEQUENCE_NUMBER_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_REF_SEQUENCE_NUMBER_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_REF_SEQUENCE_NUMBER_SIZE        4

static unsigned
parse_coinbasederivatives_ordersapi_ref_sequence_number(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_ref_sequence_number, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_REF_SEQUENCE_NUMBER_SIZE, COINBASEDERIVATIVES_ORDERSAPI_REF_SEQUENCE_NUMBER_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_REF_SEQUENCE_NUMBER_SIZE;
}

/* Reject Reason */
#define COINBASEDERIVATIVES_ORDERSAPI_REJECT_REASON_NAME        "Reject Reason"
#define COINBASEDERIVATIVES_ORDERSAPI_REJECT_REASON_DESCRIPTION "reason"
#define COINBASEDERIVATIVES_ORDERSAPI_REJECT_REASON_FILTER      "coinbasederivatives.ordersapi.rejectreason"
#define COINBASEDERIVATIVES_ORDERSAPI_REJECT_REASON_TYPE        FT_INT32
#define COINBASEDERIVATIVES_ORDERSAPI_REJECT_REASON_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_REJECT_REASON_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_REJECT_REASON_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_REJECT_REASON_SIZE        4

static const value_string coinbasederivatives_ordersapi_reject_reason_vals[] = {
    { 1, "Invalid Schema Id" },
    { 2, "Invalid Template Id" },
    { 3, "Invalid Block Length" },
    { 4, "Invalid Field Value" },
    { 0, NULL }
};

static unsigned
parse_coinbasederivatives_ordersapi_reject_reason(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_reject_reason, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_REJECT_REASON_SIZE, COINBASEDERIVATIVES_ORDERSAPI_REJECT_REASON_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_REJECT_REASON_SIZE;
}

/* Request Time */
#define COINBASEDERIVATIVES_ORDERSAPI_REQUEST_TIME_NAME        "Request Time"
#define COINBASEDERIVATIVES_ORDERSAPI_REQUEST_TIME_DESCRIPTION "requestTime"
#define COINBASEDERIVATIVES_ORDERSAPI_REQUEST_TIME_FILTER      "coinbasederivatives.ordersapi.requesttime"
#define COINBASEDERIVATIVES_ORDERSAPI_REQUEST_TIME_TYPE        FT_ABSOLUTE_TIME
#define COINBASEDERIVATIVES_ORDERSAPI_REQUEST_TIME_DISPLAY     ABSOLUTE_TIME_UTC
#define COINBASEDERIVATIVES_ORDERSAPI_REQUEST_TIME_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_REQUEST_TIME_ENCODING    ENC_TIME_NSECS | ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_REQUEST_TIME_SIZE        8

static unsigned
parse_coinbasederivatives_ordersapi_request_time(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_request_time, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_REQUEST_TIME_SIZE, COINBASEDERIVATIVES_ORDERSAPI_REQUEST_TIME_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_REQUEST_TIME_SIZE;
}

/* Request Trading Lock */
#define COINBASEDERIVATIVES_ORDERSAPI_REQUEST_TRADING_LOCK_NAME        "Request Trading Lock"
#define COINBASEDERIVATIVES_ORDERSAPI_REQUEST_TRADING_LOCK_DESCRIPTION "requestTradingLock"
#define COINBASEDERIVATIVES_ORDERSAPI_REQUEST_TRADING_LOCK_FILTER      "coinbasederivatives.ordersapi.requesttradinglock"
#define COINBASEDERIVATIVES_ORDERSAPI_REQUEST_TRADING_LOCK_TYPE        FT_INT8
#define COINBASEDERIVATIVES_ORDERSAPI_REQUEST_TRADING_LOCK_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_REQUEST_TRADING_LOCK_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_REQUEST_TRADING_LOCK_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_REQUEST_TRADING_LOCK_SIZE        1

static const value_string coinbasederivatives_ordersapi_request_trading_lock_vals[] = {
    { 0, "False" },
    { 1, "True" },
    { 0, NULL }
};

static unsigned
parse_coinbasederivatives_ordersapi_request_trading_lock(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_request_trading_lock, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_REQUEST_TRADING_LOCK_SIZE, COINBASEDERIVATIVES_ORDERSAPI_REQUEST_TRADING_LOCK_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_REQUEST_TRADING_LOCK_SIZE;
}

/* Resend Reject Reason */
#define COINBASEDERIVATIVES_ORDERSAPI_RESEND_REJECT_REASON_NAME        "Resend Reject Reason"
#define COINBASEDERIVATIVES_ORDERSAPI_RESEND_REJECT_REASON_DESCRIPTION "rejectReason"
#define COINBASEDERIVATIVES_ORDERSAPI_RESEND_REJECT_REASON_FILTER      "coinbasederivatives.ordersapi.resendrejectreason"
#define COINBASEDERIVATIVES_ORDERSAPI_RESEND_REJECT_REASON_TYPE        FT_INT8
#define COINBASEDERIVATIVES_ORDERSAPI_RESEND_REJECT_REASON_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_RESEND_REJECT_REASON_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_RESEND_REJECT_REASON_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_RESEND_REJECT_REASON_SIZE        1

static const value_string coinbasederivatives_ordersapi_resend_reject_reason_vals[] = {
    { 1, "Begin Exec Id Too Small" },
    { 2, "End Exec Id Too Large" },
    { 3, "Resend Already In Progress" },
    { 4, "Too Many Resend Requests" },
    { 5, "Server Error" },
    { 0, NULL }
};

static unsigned
parse_coinbasederivatives_ordersapi_resend_reject_reason(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_resend_reject_reason, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_RESEND_REJECT_REASON_SIZE, COINBASEDERIVATIVES_ORDERSAPI_RESEND_REJECT_REASON_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_RESEND_REJECT_REASON_SIZE;
}

/* Resent Event Count */
#define COINBASEDERIVATIVES_ORDERSAPI_RESENT_EVENT_COUNT_NAME        "Resent Event Count"
#define COINBASEDERIVATIVES_ORDERSAPI_RESENT_EVENT_COUNT_DESCRIPTION "resentEventCount"
#define COINBASEDERIVATIVES_ORDERSAPI_RESENT_EVENT_COUNT_FILTER      "coinbasederivatives.ordersapi.resenteventcount"
#define COINBASEDERIVATIVES_ORDERSAPI_RESENT_EVENT_COUNT_TYPE        FT_INT32
#define COINBASEDERIVATIVES_ORDERSAPI_RESENT_EVENT_COUNT_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_RESENT_EVENT_COUNT_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_RESENT_EVENT_COUNT_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_RESENT_EVENT_COUNT_SIZE        4

static unsigned
parse_coinbasederivatives_ordersapi_resent_event_count(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_resent_event_count, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_RESENT_EVENT_COUNT_SIZE, COINBASEDERIVATIVES_ORDERSAPI_RESENT_EVENT_COUNT_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_RESENT_EVENT_COUNT_SIZE;
}

/* Reserved */
#define COINBASEDERIVATIVES_ORDERSAPI_RESERVED_NAME        "Reserved"
#define COINBASEDERIVATIVES_ORDERSAPI_RESERVED_DESCRIPTION "Reserved for future use"
#define COINBASEDERIVATIVES_ORDERSAPI_RESERVED_FILTER      "coinbasederivatives.ordersapi.reserved"
#define COINBASEDERIVATIVES_ORDERSAPI_RESERVED_TYPE        FT_UINT32
#define COINBASEDERIVATIVES_ORDERSAPI_RESERVED_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_RESERVED_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_RESERVED_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_RESERVED_SIZE        4

static unsigned
parse_coinbasederivatives_ordersapi_reserved(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_reserved, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_RESERVED_SIZE, COINBASEDERIVATIVES_ORDERSAPI_RESERVED_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_RESERVED_SIZE;
}

/* Reserved 7 */
#define COINBASEDERIVATIVES_ORDERSAPI_RESERVED_7_NAME        "Reserved 7"
#define COINBASEDERIVATIVES_ORDERSAPI_RESERVED_7_DESCRIPTION "7 reserved bits"
#define COINBASEDERIVATIVES_ORDERSAPI_RESERVED_7_FILTER      "coinbasederivatives.ordersapi.reserved7"
#define COINBASEDERIVATIVES_ORDERSAPI_RESERVED_7_TYPE        FT_BOOLEAN
#define COINBASEDERIVATIVES_ORDERSAPI_RESERVED_7_DISPLAY     8
#define COINBASEDERIVATIVES_ORDERSAPI_RESERVED_7_MASK        0xFE

/* Reserved Byte */
#define COINBASEDERIVATIVES_ORDERSAPI_RESERVED_BYTE_NAME        "Reserved Byte"
#define COINBASEDERIVATIVES_ORDERSAPI_RESERVED_BYTE_DESCRIPTION "reserved"
#define COINBASEDERIVATIVES_ORDERSAPI_RESERVED_BYTE_FILTER      "coinbasederivatives.ordersapi.reservedbyte"
#define COINBASEDERIVATIVES_ORDERSAPI_RESERVED_BYTE_TYPE        FT_INT8
#define COINBASEDERIVATIVES_ORDERSAPI_RESERVED_BYTE_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_RESERVED_BYTE_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_RESERVED_BYTE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_RESERVED_BYTE_SIZE        1

static unsigned
parse_coinbasederivatives_ordersapi_reserved_byte(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_reserved_byte, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_RESERVED_BYTE_SIZE, COINBASEDERIVATIVES_ORDERSAPI_RESERVED_BYTE_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_RESERVED_BYTE_SIZE;
}

/* Reset Seq Num */
#define COINBASEDERIVATIVES_ORDERSAPI_RESET_SEQ_NUM_NAME        "Reset Seq Num"
#define COINBASEDERIVATIVES_ORDERSAPI_RESET_SEQ_NUM_DESCRIPTION "resetSeqNum"
#define COINBASEDERIVATIVES_ORDERSAPI_RESET_SEQ_NUM_FILTER      "coinbasederivatives.ordersapi.resetseqnum"
#define COINBASEDERIVATIVES_ORDERSAPI_RESET_SEQ_NUM_TYPE        FT_INT8
#define COINBASEDERIVATIVES_ORDERSAPI_RESET_SEQ_NUM_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_RESET_SEQ_NUM_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_RESET_SEQ_NUM_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_RESET_SEQ_NUM_SIZE        1

static const value_string coinbasederivatives_ordersapi_reset_seq_num_vals[] = {
    { 0, "False" },
    { 1, "True" },
    { 0, NULL }
};

static unsigned
parse_coinbasederivatives_ordersapi_reset_seq_num(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_reset_seq_num, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_RESET_SEQ_NUM_SIZE, COINBASEDERIVATIVES_ORDERSAPI_RESET_SEQ_NUM_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_RESET_SEQ_NUM_SIZE;
}

/* Schema Id values the dispatch switches on */
#define COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_SESSION 1100
#define COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_ORDER   1101

/* Schema Id */
#define COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_NAME        "Schema Id"
#define COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_DESCRIPTION "Identifier of the schema publishing the message"
#define COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_FILTER      "coinbasederivatives.ordersapi.schemaid"
#define COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_TYPE        FT_UINT16
#define COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_SIZE        2

static const value_string coinbasederivatives_ordersapi_schema_id_vals[] = {
    { COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_SESSION, "Session" },
    { COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_ORDER, "Order" },
    { 0, NULL }
};

static unsigned
parse_coinbasederivatives_ordersapi_schema_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_schema_id, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_SIZE, COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_SIZE;
}

/* Security Type */
#define COINBASEDERIVATIVES_ORDERSAPI_SECURITY_TYPE_NAME        "Security Type"
#define COINBASEDERIVATIVES_ORDERSAPI_SECURITY_TYPE_DESCRIPTION "securityType"
#define COINBASEDERIVATIVES_ORDERSAPI_SECURITY_TYPE_FILTER      "coinbasederivatives.ordersapi.securitytype"
#define COINBASEDERIVATIVES_ORDERSAPI_SECURITY_TYPE_TYPE        FT_UINT8
#define COINBASEDERIVATIVES_ORDERSAPI_SECURITY_TYPE_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_SECURITY_TYPE_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_SECURITY_TYPE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_SECURITY_TYPE_SIZE        1

static const value_string coinbasederivatives_ordersapi_security_type_vals[] = {
    { 0, "Futures" },
    { 1, "Options" },
    { 0, NULL }
};

static unsigned
parse_coinbasederivatives_ordersapi_security_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_security_type, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_SECURITY_TYPE_SIZE, COINBASEDERIVATIVES_ORDERSAPI_SECURITY_TYPE_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_SECURITY_TYPE_SIZE;
}

/* Send Time Epoch Nanos */
#define COINBASEDERIVATIVES_ORDERSAPI_SEND_TIME_EPOCH_NANOS_NAME        "Send Time Epoch Nanos"
#define COINBASEDERIVATIVES_ORDERSAPI_SEND_TIME_EPOCH_NANOS_DESCRIPTION "UTC timestamp of when the message was sent, nanoseconds since Unix epoch (January 1st, 1970, 00:00:00 GMT)"
#define COINBASEDERIVATIVES_ORDERSAPI_SEND_TIME_EPOCH_NANOS_FILTER      "coinbasederivatives.ordersapi.sendtimeepochnanos"
#define COINBASEDERIVATIVES_ORDERSAPI_SEND_TIME_EPOCH_NANOS_TYPE        FT_ABSOLUTE_TIME
#define COINBASEDERIVATIVES_ORDERSAPI_SEND_TIME_EPOCH_NANOS_DISPLAY     ABSOLUTE_TIME_UTC
#define COINBASEDERIVATIVES_ORDERSAPI_SEND_TIME_EPOCH_NANOS_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_SEND_TIME_EPOCH_NANOS_ENCODING    ENC_TIME_NSECS | ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_SEND_TIME_EPOCH_NANOS_SIZE        8

static unsigned
parse_coinbasederivatives_ordersapi_send_time_epoch_nanos(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_send_time_epoch_nanos, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_SEND_TIME_EPOCH_NANOS_SIZE, COINBASEDERIVATIVES_ORDERSAPI_SEND_TIME_EPOCH_NANOS_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_SEND_TIME_EPOCH_NANOS_SIZE;
}

/* Sequence Number */
#define COINBASEDERIVATIVES_ORDERSAPI_SEQUENCE_NUMBER_NAME        "Sequence Number"
#define COINBASEDERIVATIVES_ORDERSAPI_SEQUENCE_NUMBER_DESCRIPTION "Outbound sequence number per session"
#define COINBASEDERIVATIVES_ORDERSAPI_SEQUENCE_NUMBER_FILTER      "coinbasederivatives.ordersapi.sequencenumber"
#define COINBASEDERIVATIVES_ORDERSAPI_SEQUENCE_NUMBER_TYPE        FT_UINT32
#define COINBASEDERIVATIVES_ORDERSAPI_SEQUENCE_NUMBER_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_SEQUENCE_NUMBER_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_SEQUENCE_NUMBER_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_SEQUENCE_NUMBER_SIZE        4

static unsigned
parse_coinbasederivatives_ordersapi_sequence_number(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_sequence_number, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_SEQUENCE_NUMBER_SIZE, COINBASEDERIVATIVES_ORDERSAPI_SEQUENCE_NUMBER_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_SEQUENCE_NUMBER_SIZE;
}

/* Server Time */
#define COINBASEDERIVATIVES_ORDERSAPI_SERVER_TIME_NAME        "Server Time"
#define COINBASEDERIVATIVES_ORDERSAPI_SERVER_TIME_DESCRIPTION "serverTime"
#define COINBASEDERIVATIVES_ORDERSAPI_SERVER_TIME_FILTER      "coinbasederivatives.ordersapi.servertime"
#define COINBASEDERIVATIVES_ORDERSAPI_SERVER_TIME_TYPE        FT_ABSOLUTE_TIME
#define COINBASEDERIVATIVES_ORDERSAPI_SERVER_TIME_DISPLAY     ABSOLUTE_TIME_UTC
#define COINBASEDERIVATIVES_ORDERSAPI_SERVER_TIME_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_SERVER_TIME_ENCODING    ENC_TIME_NSECS | ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_SERVER_TIME_SIZE        8

static unsigned
parse_coinbasederivatives_ordersapi_server_time(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_server_time, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_SERVER_TIME_SIZE, COINBASEDERIVATIVES_ORDERSAPI_SERVER_TIME_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_SERVER_TIME_SIZE;
}

/* Side */
#define COINBASEDERIVATIVES_ORDERSAPI_SIDE_NAME        "Side"
#define COINBASEDERIVATIVES_ORDERSAPI_SIDE_DESCRIPTION "1 buy, -1 sell"
#define COINBASEDERIVATIVES_ORDERSAPI_SIDE_FILTER      "coinbasederivatives.ordersapi.side"
#define COINBASEDERIVATIVES_ORDERSAPI_SIDE_TYPE        FT_INT8
#define COINBASEDERIVATIVES_ORDERSAPI_SIDE_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_SIDE_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_SIDE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_SIDE_SIZE        1

static const value_string coinbasederivatives_ordersapi_side_vals[] = {
    { 1, "Buy" },
    { -1, "Sell" },
    { 0, NULL }
};

static unsigned
parse_coinbasederivatives_ordersapi_side(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_side, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_SIDE_SIZE, COINBASEDERIVATIVES_ORDERSAPI_SIDE_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_SIDE_SIZE;
}

/* Symbol */
#define COINBASEDERIVATIVES_ORDERSAPI_SYMBOL_NAME        "Symbol"
#define COINBASEDERIVATIVES_ORDERSAPI_SYMBOL_DESCRIPTION "Instrument symbol"
#define COINBASEDERIVATIVES_ORDERSAPI_SYMBOL_FILTER      "coinbasederivatives.ordersapi.symbol"
#define COINBASEDERIVATIVES_ORDERSAPI_SYMBOL_TYPE        FT_STRING
#define COINBASEDERIVATIVES_ORDERSAPI_SYMBOL_DISPLAY     BASE_NONE
#define COINBASEDERIVATIVES_ORDERSAPI_SYMBOL_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_SYMBOL_ENCODING    ENC_ASCII
#define COINBASEDERIVATIVES_ORDERSAPI_SYMBOL_SIZE        32

static unsigned
parse_coinbasederivatives_ordersapi_symbol(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_symbol, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_SYMBOL_SIZE, COINBASEDERIVATIVES_ORDERSAPI_SYMBOL_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_SYMBOL_SIZE;
}

/* Template Id values the dispatch switches on */
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGON                        100
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGON_CONF                   200
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGOUT                       101
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGGED_OUT                   201
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_HEARTBEAT                    10
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_TEST_REQUEST                 11
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_RESEND_REQUEST               102
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_GAP_FILL                     202
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_REJECT                               210
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_INSTRUMENT_INFO_REQUEST              103
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_INSTRUMENT_INFO                      203
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SET_ACCOUNT                          105
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SET_TRADER                           106
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SET_ACK                              205
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_NEW_ORDER                            110
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_NEW_IOC_ORDER                        111
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_REPLACE_ORDER                        120
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_OBSOLETE_STREAM_ORDER                121
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_REJECT                         221
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_REPLACED                       220
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER                         130
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_CANCELED                       230
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_REJECT                  233
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_ORDER                    131
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_ORDER_ACK                231
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_ORDER_REJECT             232
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_UNLOCK_TRADING                       132
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_UNLOCK_TRADING_ACK                   234
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_UNLOCK_TRADING_REJECT                235
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_FILLED                         240
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SPREAD_ORDER_FILLED                  241
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_LAST_EXEC_ID_REQUEST                 150
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_LAST_EXEC_ID                         250
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_EVENT_RESEND_REQUEST                 152
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_EVENT_RESEND_COMPLETE                252
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_EVENT_RESEND_REJECT                  253
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_RESET_OPTIONS_FILL_PROTECTION        160
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_RESET_OPTIONS_FILL_PROTECTION_ACK    260
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_RESET_OPTIONS_FILL_PROTECTION_REJECT 261

/* Template Id */
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_NAME        "Template Id"
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_DESCRIPTION "Template ID used to encode the message"
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_FILTER      "coinbasederivatives.ordersapi.templateid"
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_TYPE        FT_UINT16
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SIZE        2

static const value_string coinbasederivatives_ordersapi_template_id_vals[] = {
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGON, "Session Logon Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGON_CONF, "Session Logon Conf Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGOUT, "Session Logout Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGGED_OUT, "Session Logged Out Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_HEARTBEAT, "Session Heartbeat Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_TEST_REQUEST, "Session Test Request Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_RESEND_REQUEST, "Session Resend Request Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_GAP_FILL, "Session Gap Fill Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_REJECT, "Reject Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_INSTRUMENT_INFO_REQUEST, "Instrument Info Request Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_INSTRUMENT_INFO, "Instrument Info Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SET_ACCOUNT, "Set Account Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SET_TRADER, "Set Trader Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SET_ACK, "Set Ack Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_NEW_ORDER, "New Order Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_NEW_IOC_ORDER, "New Ioc Order Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_REPLACE_ORDER, "Replace Order Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_OBSOLETE_STREAM_ORDER, "Obsolete Stream Order Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_REJECT, "Order Reject Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_REPLACED, "Order Replaced Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER, "Cancel Order Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_CANCELED, "Order Canceled Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_REJECT, "Cancel Order Reject Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_ORDER, "Mass Cancel Order Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_ORDER_ACK, "Mass Cancel Order Ack Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_ORDER_REJECT, "Mass Cancel Order Reject Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_UNLOCK_TRADING, "Unlock Trading Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_UNLOCK_TRADING_ACK, "Unlock Trading Ack Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_UNLOCK_TRADING_REJECT, "Unlock Trading Reject Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_FILLED, "Order Filled Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SPREAD_ORDER_FILLED, "Spread Order Filled Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_LAST_EXEC_ID_REQUEST, "Last Exec Id Request Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_LAST_EXEC_ID, "Last Exec Id Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_EVENT_RESEND_REQUEST, "Event Resend Request Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_EVENT_RESEND_COMPLETE, "Event Resend Complete Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_EVENT_RESEND_REJECT, "Event Resend Reject Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_RESET_OPTIONS_FILL_PROTECTION, "Reset Options Fill Protection Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_RESET_OPTIONS_FILL_PROTECTION_ACK, "Reset Options Fill Protection Ack Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_RESET_OPTIONS_FILL_PROTECTION_REJECT, "Reset Options Fill Protection Reject Message" },
    { 0, NULL }
};

static unsigned
parse_coinbasederivatives_ordersapi_template_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_template_id, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SIZE, COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SIZE;
}

/* Time In Force */
#define COINBASEDERIVATIVES_ORDERSAPI_TIME_IN_FORCE_NAME        "Time In Force"
#define COINBASEDERIVATIVES_ORDERSAPI_TIME_IN_FORCE_DESCRIPTION "timeInForce"
#define COINBASEDERIVATIVES_ORDERSAPI_TIME_IN_FORCE_FILTER      "coinbasederivatives.ordersapi.timeinforce"
#define COINBASEDERIVATIVES_ORDERSAPI_TIME_IN_FORCE_TYPE        FT_INT8
#define COINBASEDERIVATIVES_ORDERSAPI_TIME_IN_FORCE_DISPLAY     BASE_CUSTOM
#define COINBASEDERIVATIVES_ORDERSAPI_TIME_IN_FORCE_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_TIME_IN_FORCE_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_TIME_IN_FORCE_SIZE        1

static const value_string coinbasederivatives_ordersapi_time_in_force_vals[] = {
    { 0, "Day" },
    { 1, "Good Till Date" },
    { 0, NULL }
};

/* Format the sentinel's label alone, an enumerated value labelled */
static void
coinbasederivatives_ordersapi_format_time_in_force(char *buf, uint32_t raw)
{
    int64_t value = (int32_t)raw;

    if (value == INT8_MIN) {
        snprintf(buf, ITEM_LABEL_LENGTH, "%s", "No Value");
        return;
    }

    snprintf(buf, ITEM_LABEL_LENGTH, "%s (%" PRId64 ")", val_to_str_const(raw, coinbasederivatives_ordersapi_time_in_force_vals, "Unknown"), value);
}

static unsigned
parse_coinbasederivatives_ordersapi_time_in_force(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_time_in_force, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_TIME_IN_FORCE_SIZE, COINBASEDERIVATIVES_ORDERSAPI_TIME_IN_FORCE_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_TIME_IN_FORCE_SIZE;
}

/* Timestamp */
#define COINBASEDERIVATIVES_ORDERSAPI_TIMESTAMP_NAME        "Timestamp"
#define COINBASEDERIVATIVES_ORDERSAPI_TIMESTAMP_DESCRIPTION "Nanoseconds since epoch"
#define COINBASEDERIVATIVES_ORDERSAPI_TIMESTAMP_FILTER      "coinbasederivatives.ordersapi.timestamp"
#define COINBASEDERIVATIVES_ORDERSAPI_TIMESTAMP_TYPE        FT_ABSOLUTE_TIME
#define COINBASEDERIVATIVES_ORDERSAPI_TIMESTAMP_DISPLAY     ABSOLUTE_TIME_UTC
#define COINBASEDERIVATIVES_ORDERSAPI_TIMESTAMP_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_TIMESTAMP_ENCODING    ENC_TIME_NSECS | ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_TIMESTAMP_SIZE        8

static unsigned
parse_coinbasederivatives_ordersapi_timestamp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_timestamp, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_TIMESTAMP_SIZE, COINBASEDERIVATIVES_ORDERSAPI_TIMESTAMP_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_TIMESTAMP_SIZE;
}

/* To Sequence Number */
#define COINBASEDERIVATIVES_ORDERSAPI_TO_SEQUENCE_NUMBER_NAME        "To Sequence Number"
#define COINBASEDERIVATIVES_ORDERSAPI_TO_SEQUENCE_NUMBER_DESCRIPTION "toSequenceNumber"
#define COINBASEDERIVATIVES_ORDERSAPI_TO_SEQUENCE_NUMBER_FILTER      "coinbasederivatives.ordersapi.tosequencenumber"
#define COINBASEDERIVATIVES_ORDERSAPI_TO_SEQUENCE_NUMBER_TYPE        FT_UINT32
#define COINBASEDERIVATIVES_ORDERSAPI_TO_SEQUENCE_NUMBER_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_TO_SEQUENCE_NUMBER_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_TO_SEQUENCE_NUMBER_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_TO_SEQUENCE_NUMBER_SIZE        4

static unsigned
parse_coinbasederivatives_ordersapi_to_sequence_number(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_to_sequence_number, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_TO_SEQUENCE_NUMBER_SIZE, COINBASEDERIVATIVES_ORDERSAPI_TO_SEQUENCE_NUMBER_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_TO_SEQUENCE_NUMBER_SIZE;
}

/* Total Filled */
#define COINBASEDERIVATIVES_ORDERSAPI_TOTAL_FILLED_NAME        "Total Filled"
#define COINBASEDERIVATIVES_ORDERSAPI_TOTAL_FILLED_DESCRIPTION "totalFilled"
#define COINBASEDERIVATIVES_ORDERSAPI_TOTAL_FILLED_FILTER      "coinbasederivatives.ordersapi.totalfilled"
#define COINBASEDERIVATIVES_ORDERSAPI_TOTAL_FILLED_TYPE        FT_INT32
#define COINBASEDERIVATIVES_ORDERSAPI_TOTAL_FILLED_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_TOTAL_FILLED_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_TOTAL_FILLED_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_TOTAL_FILLED_SIZE        4

static unsigned
parse_coinbasederivatives_ordersapi_total_filled(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_total_filled, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_TOTAL_FILLED_SIZE, COINBASEDERIVATIVES_ORDERSAPI_TOTAL_FILLED_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_TOTAL_FILLED_SIZE;
}

/* Trader */
#define COINBASEDERIVATIVES_ORDERSAPI_TRADER_NAME        "Trader"
#define COINBASEDERIVATIVES_ORDERSAPI_TRADER_DESCRIPTION "Trader, a zero padded ascii string"
#define COINBASEDERIVATIVES_ORDERSAPI_TRADER_FILTER      "coinbasederivatives.ordersapi.trader"
#define COINBASEDERIVATIVES_ORDERSAPI_TRADER_TYPE        FT_STRING
#define COINBASEDERIVATIVES_ORDERSAPI_TRADER_DISPLAY     BASE_NONE
#define COINBASEDERIVATIVES_ORDERSAPI_TRADER_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_TRADER_ENCODING    ENC_ASCII
#define COINBASEDERIVATIVES_ORDERSAPI_TRADER_SIZE        16

static unsigned
parse_coinbasederivatives_ordersapi_trader(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_trader, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_TRADER_SIZE, COINBASEDERIVATIVES_ORDERSAPI_TRADER_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_TRADER_SIZE;
}

/* Trading Instrument Status */
#define COINBASEDERIVATIVES_ORDERSAPI_TRADING_INSTRUMENT_STATUS_NAME        "Trading Instrument Status"
#define COINBASEDERIVATIVES_ORDERSAPI_TRADING_INSTRUMENT_STATUS_DESCRIPTION "status"
#define COINBASEDERIVATIVES_ORDERSAPI_TRADING_INSTRUMENT_STATUS_FILTER      "coinbasederivatives.ordersapi.tradinginstrumentstatus"
#define COINBASEDERIVATIVES_ORDERSAPI_TRADING_INSTRUMENT_STATUS_TYPE        FT_INT8
#define COINBASEDERIVATIVES_ORDERSAPI_TRADING_INSTRUMENT_STATUS_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_TRADING_INSTRUMENT_STATUS_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_TRADING_INSTRUMENT_STATUS_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_TRADING_INSTRUMENT_STATUS_SIZE        1

static const value_string coinbasederivatives_ordersapi_trading_instrument_status_vals[] = {
    { 0, "Ok" },
    { 1, "Temporarily Unavailable" },
    { 2, "Back Pressured" },
    { 0, NULL }
};

static unsigned
parse_coinbasederivatives_ordersapi_trading_instrument_status(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_trading_instrument_status, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_TRADING_INSTRUMENT_STATUS_SIZE, COINBASEDERIVATIVES_ORDERSAPI_TRADING_INSTRUMENT_STATUS_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_TRADING_INSTRUMENT_STATUS_SIZE;
}

/* Trading Lock Applied */
#define COINBASEDERIVATIVES_ORDERSAPI_TRADING_LOCK_APPLIED_NAME        "Trading Lock Applied"
#define COINBASEDERIVATIVES_ORDERSAPI_TRADING_LOCK_APPLIED_DESCRIPTION "tradingLockApplied"
#define COINBASEDERIVATIVES_ORDERSAPI_TRADING_LOCK_APPLIED_FILTER      "coinbasederivatives.ordersapi.tradinglockapplied"
#define COINBASEDERIVATIVES_ORDERSAPI_TRADING_LOCK_APPLIED_TYPE        FT_INT8
#define COINBASEDERIVATIVES_ORDERSAPI_TRADING_LOCK_APPLIED_DISPLAY     BASE_DEC
#define COINBASEDERIVATIVES_ORDERSAPI_TRADING_LOCK_APPLIED_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_TRADING_LOCK_APPLIED_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_TRADING_LOCK_APPLIED_SIZE        1

static const value_string coinbasederivatives_ordersapi_trading_lock_applied_vals[] = {
    { 0, "False" },
    { 1, "True" },
    { 0, NULL }
};

static unsigned
parse_coinbasederivatives_ordersapi_trading_lock_applied(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_trading_lock_applied, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_TRADING_LOCK_APPLIED_SIZE, COINBASEDERIVATIVES_ORDERSAPI_TRADING_LOCK_APPLIED_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_TRADING_LOCK_APPLIED_SIZE;
}

/* Username */
#define COINBASEDERIVATIVES_ORDERSAPI_USERNAME_NAME        "Username"
#define COINBASEDERIVATIVES_ORDERSAPI_USERNAME_DESCRIPTION "Logon username"
#define COINBASEDERIVATIVES_ORDERSAPI_USERNAME_FILTER      "coinbasederivatives.ordersapi.username"
#define COINBASEDERIVATIVES_ORDERSAPI_USERNAME_TYPE        FT_STRING
#define COINBASEDERIVATIVES_ORDERSAPI_USERNAME_DISPLAY     BASE_NONE
#define COINBASEDERIVATIVES_ORDERSAPI_USERNAME_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_USERNAME_ENCODING    ENC_ASCII
#define COINBASEDERIVATIVES_ORDERSAPI_USERNAME_SIZE        16

static unsigned
parse_coinbasederivatives_ordersapi_username(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_username, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_USERNAME_SIZE, COINBASEDERIVATIVES_ORDERSAPI_USERNAME_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_USERNAME_SIZE;
}

/* Version */
#define COINBASEDERIVATIVES_ORDERSAPI_VERSION_NAME        "Version"
#define COINBASEDERIVATIVES_ORDERSAPI_VERSION_DESCRIPTION "Schema version"
#define COINBASEDERIVATIVES_ORDERSAPI_VERSION_FILTER      "coinbasederivatives.ordersapi.version"
#define COINBASEDERIVATIVES_ORDERSAPI_VERSION_TYPE        FT_UINT16
#define COINBASEDERIVATIVES_ORDERSAPI_VERSION_DISPLAY     BASE_HEX
#define COINBASEDERIVATIVES_ORDERSAPI_VERSION_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_VERSION_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_VERSION_SIZE        2

static unsigned
parse_coinbasederivatives_ordersapi_version(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_item(tree, hf_coinbasederivatives_ordersapi_version, tvb, offset, COINBASEDERIVATIVES_ORDERSAPI_VERSION_SIZE, COINBASEDERIVATIVES_ORDERSAPI_VERSION_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_VERSION_SIZE;
}

/*
 * CoinbaseDerivatives OrdersApi Structs
 */

/* Flags */
#define COINBASEDERIVATIVES_ORDERSAPI_FLAGS_NAME        "Flags"
#define COINBASEDERIVATIVES_ORDERSAPI_FLAGS_DESCRIPTION "NewOrderFlags bit set"
#define COINBASEDERIVATIVES_ORDERSAPI_FLAGS_FILTER      "coinbasederivatives.ordersapi.flags"
#define COINBASEDERIVATIVES_ORDERSAPI_FLAGS_TYPE        FT_UINT8
#define COINBASEDERIVATIVES_ORDERSAPI_FLAGS_DISPLAY     BASE_HEX
#define COINBASEDERIVATIVES_ORDERSAPI_FLAGS_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_FLAGS_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_FLAGS_SIZE        1

static int * const coinbasederivatives_ordersapi_flags_fields[] = {
    &hf_coinbasederivatives_ordersapi_reserved_7,
    &hf_coinbasederivatives_ordersapi_post_only,
    NULL
};

static unsigned
parse_coinbasederivatives_ordersapi_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_bitmask(tree, tvb, offset, hf_coinbasederivatives_ordersapi_flags,
        ett_coinbasederivatives_ordersapi_flags, coinbasederivatives_ordersapi_flags_fields, COINBASEDERIVATIVES_ORDERSAPI_FLAGS_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_FLAGS_SIZE;
}

/* Flags */
#define COINBASEDERIVATIVES_ORDERSAPI_FLAGS_V15_NAME        "Flags"
#define COINBASEDERIVATIVES_ORDERSAPI_FLAGS_V15_DESCRIPTION "Uint8 bit set carrying the isResend indicator"
#define COINBASEDERIVATIVES_ORDERSAPI_FLAGS_V15_FILTER      "coinbasederivatives.ordersapi.flags"
#define COINBASEDERIVATIVES_ORDERSAPI_FLAGS_V15_TYPE        FT_UINT8
#define COINBASEDERIVATIVES_ORDERSAPI_FLAGS_V15_DISPLAY     BASE_HEX
#define COINBASEDERIVATIVES_ORDERSAPI_FLAGS_V15_MASK        0x0
#define COINBASEDERIVATIVES_ORDERSAPI_FLAGS_V15_ENCODING    ENC_LITTLE_ENDIAN
#define COINBASEDERIVATIVES_ORDERSAPI_FLAGS_V15_SIZE        1

static int * const coinbasederivatives_ordersapi_flags_v15_fields[] = {
    &hf_coinbasederivatives_ordersapi_is_resend,
    NULL
};

static unsigned
parse_coinbasederivatives_ordersapi_flags_v15(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned offset)
{
    proto_tree_add_bitmask(tree, tvb, offset, hf_coinbasederivatives_ordersapi_flags_v15,
        ett_coinbasederivatives_ordersapi_flags_v15, coinbasederivatives_ordersapi_flags_v15_fields, COINBASEDERIVATIVES_ORDERSAPI_FLAGS_V15_ENCODING);

    return offset + COINBASEDERIVATIVES_ORDERSAPI_FLAGS_V15_SIZE;
}

/* Message and group dissect methods */
static unsigned dissect_coinbasederivatives_ordersapi_message_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_session(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_order(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_logon(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_logon_conf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_logout(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_logged_out(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_heartbeat(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_test_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_resend_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_gap_fill(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_reject(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_ping(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_pong(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_instrument_info_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_instrument_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_set_account(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_set_trader(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_set_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_new_order(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_new_ioc_order(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_order_entered(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_replace_order(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_obsolete_stream_order(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_order_reject(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_order_replaced(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_cancel_order(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_order_canceled(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_cancel_order_reject(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_mass_cancel_order(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_mass_cancel_order_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_mass_cancel_order_reject(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_unlock_trading(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_unlock_trading_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_unlock_trading_reject(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_order_filled(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_spread_order_filled(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_last_exec_id_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_last_exec_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_event_resend_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_event_resend_complete(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_event_resend_reject(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_reset_options_fill_protection(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_reset_options_fill_protection_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_reset_options_fill_protection_reject(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_session_v17(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_order_v17(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_logout_v17(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_logged_out_v17(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_session_v16(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_logout_v16(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_logged_out_v16(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_message_header_v15(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_session_v15(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_order_v15(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_logout_v15(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_logged_out_v15(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_new_order_v15(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_replace_order_v15(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_stream_order(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_event_resend_reject_v15(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_session_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_order_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_logout_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_logged_out_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_new_order_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_replace_order_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_event_resend_reject_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_session_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_order_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_logout_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_logged_out_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_new_order_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_replace_order_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_stream_order_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_mass_cancel_order_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_order_filled_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_spread_order_filled_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_event_resend_reject_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset);
static unsigned dissect_coinbasederivatives_ordersapi_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t schema_id);
static unsigned dissect_coinbasederivatives_ordersapi_payload_v17(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t schema_id);
static unsigned dissect_coinbasederivatives_ordersapi_payload_v16(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t schema_id);
static unsigned dissect_coinbasederivatives_ordersapi_payload_v15(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t schema_id);
static unsigned dissect_coinbasederivatives_ordersapi_payload_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t schema_id);
static unsigned dissect_coinbasederivatives_ordersapi_payload_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t schema_id);
static unsigned dissect_coinbasederivatives_ordersapi_session_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id);
static unsigned dissect_coinbasederivatives_ordersapi_session_payload_v17(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id);
static unsigned dissect_coinbasederivatives_ordersapi_session_payload_v16(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id);
static unsigned dissect_coinbasederivatives_ordersapi_session_payload_v15(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id);
static unsigned dissect_coinbasederivatives_ordersapi_session_payload_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id);
static unsigned dissect_coinbasederivatives_ordersapi_session_payload_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id);
static unsigned dissect_coinbasederivatives_ordersapi_order_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id);
static unsigned dissect_coinbasederivatives_ordersapi_order_payload_v17(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id);
static unsigned dissect_coinbasederivatives_ordersapi_order_payload_v15(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id);
static unsigned dissect_coinbasederivatives_ordersapi_order_payload_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id);
static unsigned dissect_coinbasederivatives_ordersapi_order_payload_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id);

/* Message Header */
static unsigned
dissect_coinbasederivatives_ordersapi_message_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (coinbasederivatives_ordersapi_show_headers) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_coinbasederivatives_ordersapi_message_header, &item, "Message Header");
    }

    unsigned start = offset;

    offset = parse_coinbasederivatives_ordersapi_protocol_id(tvb, pinfo, group, offset);
    offset = parse_coinbasederivatives_ordersapi_flags(tvb, pinfo, group, offset);
    offset = parse_coinbasederivatives_ordersapi_message_length(tvb, pinfo, group, offset);
    offset = parse_coinbasederivatives_ordersapi_sequence_number(tvb, pinfo, group, offset);
    offset = parse_coinbasederivatives_ordersapi_last_processed_seq_no(tvb, pinfo, group, offset);
    offset = parse_coinbasederivatives_ordersapi_reserved(tvb, pinfo, group, offset);
    offset = parse_coinbasederivatives_ordersapi_send_time_epoch_nanos(tvb, pinfo, group, offset);
    offset = parse_coinbasederivatives_ordersapi_block_length(tvb, pinfo, group, offset);
    offset = parse_coinbasederivatives_ordersapi_template_id(tvb, pinfo, group, offset);
    offset = parse_coinbasederivatives_ordersapi_schema_id(tvb, pinfo, group, offset);
    offset = parse_coinbasederivatives_ordersapi_version(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Session Message */
static unsigned
dissect_coinbasederivatives_ordersapi_session(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;


    uint32_t template_id = tvb_get_letohs(tvb, start);

    offset = dissect_coinbasederivatives_ordersapi_session_payload(tvb, pinfo, tree, offset, template_id);

    return offset;
}

/* Order Message */
static unsigned
dissect_coinbasederivatives_ordersapi_order(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;


    uint32_t template_id = tvb_get_letohs(tvb, start);

    offset = dissect_coinbasederivatives_ordersapi_order_payload(tvb, pinfo, tree, offset, template_id);

    return offset;
}

/* Logon Message */
static unsigned
dissect_coinbasederivatives_ordersapi_logon(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_username(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_password(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_reset_seq_num(tvb, pinfo, tree, offset);

    return offset;
}

/* Logon Conf Message */
static unsigned
dissect_coinbasederivatives_ordersapi_logon_conf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_heartbeat_interval_seconds(tvb, pinfo, tree, offset);

    return offset;
}

/* Logout Message */
static unsigned
dissect_coinbasederivatives_ordersapi_logout(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_reason_string_64(tvb, pinfo, tree, offset);

    return offset;
}

/* Logged Out Message */
static unsigned
dissect_coinbasederivatives_ordersapi_logged_out(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_reason_string_64(tvb, pinfo, tree, offset);

    return offset;
}

/* Heartbeat Message */
static unsigned
dissect_coinbasederivatives_ordersapi_heartbeat(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);

    return offset;
}

/* Test Request Message */
static unsigned
dissect_coinbasederivatives_ordersapi_test_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);

    return offset;
}

/* Resend Request Message */
static unsigned
dissect_coinbasederivatives_ordersapi_resend_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_from_sequence_number(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_to_sequence_number(tvb, pinfo, tree, offset);

    return offset;
}

/* Gap Fill Message */
static unsigned
dissect_coinbasederivatives_ordersapi_gap_fill(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_new_sequence_number(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_gap_fill_padding(tvb, pinfo, tree, offset);

    return offset;
}

/* Reject Message */
static unsigned
dissect_coinbasederivatives_ordersapi_reject(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_ref_sequence_number(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_reject_reason(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_details(tvb, pinfo, tree, offset);

    return offset;
}

/* Ping Message */
static unsigned
dissect_coinbasederivatives_ordersapi_ping(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_request_time(tvb, pinfo, tree, offset);
    offset = dissect_coinbasederivatives_ordersapi_data(tvb, pinfo, tree, offset);

    return offset;
}

/* Data */
static unsigned
dissect_coinbasederivatives_ordersapi_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (coinbasederivatives_ordersapi_show_structs) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_coinbasederivatives_ordersapi_data, &item, "Data");
    }

    unsigned start = offset;

    offset = parse_coinbasederivatives_ordersapi_data_length(tvb, pinfo, group, offset);
    /* Data Value is a placeholder, it consumes no bytes */

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Pong Message */
static unsigned
dissect_coinbasederivatives_ordersapi_pong(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_request_time(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_server_time(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_trading_instrument_status(tvb, pinfo, tree, offset);
    offset = dissect_coinbasederivatives_ordersapi_data(tvb, pinfo, tree, offset);

    return offset;
}

/* Instrument Info Request Message */
static unsigned
dissect_coinbasederivatives_ordersapi_instrument_info_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);

    return offset;
}

/* Instrument Info Message */
static unsigned
dissect_coinbasederivatives_ordersapi_instrument_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_security_type(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_instrument_status(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_is_last_message(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_reserved_byte(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_symbol(tvb, pinfo, tree, offset);

    return offset;
}

/* Set Account Message */
static unsigned
dissect_coinbasederivatives_ordersapi_set_account(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_account(tvb, pinfo, tree, offset);

    return offset;
}

/* Set Trader Message */
static unsigned
dissect_coinbasederivatives_ordersapi_set_trader(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_trader(tvb, pinfo, tree, offset);

    return offset;
}

/* Set Ack Message */
static unsigned
dissect_coinbasederivatives_ordersapi_set_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);

    return offset;
}

/* New Order Message */
static unsigned
dissect_coinbasederivatives_ordersapi_new_order(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_client_order_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_limit_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_quantity(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_side(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_flags(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_good_til_date(tvb, pinfo, tree, offset);

    return offset;
}

/* New Ioc Order Message */
static unsigned
dissect_coinbasederivatives_ordersapi_new_ioc_order(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_client_order_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_limit_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_quantity(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_min_qty(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_side(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Entered Message */
static unsigned
dissect_coinbasederivatives_ordersapi_order_entered(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_exec_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_client_order_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_order_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_receive_time(tvb, pinfo, tree, offset);

    return offset;
}

/* Replace Order Message */
static unsigned
dissect_coinbasederivatives_ordersapi_replace_order(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_client_order_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_new_limit_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_new_quantity(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_good_til_date(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_time_in_force(tvb, pinfo, tree, offset);

    return offset;
}

/* Obsolete Stream Order Message */
static unsigned
dissect_coinbasederivatives_ordersapi_obsolete_stream_order(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_client_order_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_last_processed_fill_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_limit_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_quantity(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_side(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Reject Message */
static unsigned
dissect_coinbasederivatives_ordersapi_order_reject(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_client_order_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_order_id_optional(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_order_reject_reason(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_order_reject_details(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Replaced Message */
static unsigned
dissect_coinbasederivatives_ordersapi_order_replaced(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_exec_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_client_order_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_order_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_receive_time(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_total_filled(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_available_qty(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_instrument_id(tvb, pinfo, tree, offset);

    return offset;
}

/* Cancel Order Message */
static unsigned
dissect_coinbasederivatives_ordersapi_cancel_order(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_client_order_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_instrument_id(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Canceled Message */
static unsigned
dissect_coinbasederivatives_ordersapi_order_canceled(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_exec_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_client_order_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_order_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_receive_time(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_total_filled(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_cancel_reason(tvb, pinfo, tree, offset);

    return offset;
}

/* Cancel Order Reject Message */
static unsigned
dissect_coinbasederivatives_ordersapi_cancel_order_reject(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_client_order_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_order_id_optional(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_cancel_order_reject_reason(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_cancel_order_reject_details(tvb, pinfo, tree, offset);

    return offset;
}

/* Mass Cancel Order Message */
static unsigned
dissect_coinbasederivatives_ordersapi_mass_cancel_order(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_limit_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_side(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_current_session_only(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_request_trading_lock(tvb, pinfo, tree, offset);

    return offset;
}

/* Mass Cancel Order Ack Message */
static unsigned
dissect_coinbasederivatives_ordersapi_mass_cancel_order_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_exec_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_canceled_count(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_only_current_session(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_trading_lock_applied(tvb, pinfo, tree, offset);

    return offset;
}

/* Mass Cancel Order Reject Message */
static unsigned
dissect_coinbasederivatives_ordersapi_mass_cancel_order_reject(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_error_message(tvb, pinfo, tree, offset);

    return offset;
}

/* Unlock Trading Message */
static unsigned
dissect_coinbasederivatives_ordersapi_unlock_trading(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_current_session_only(tvb, pinfo, tree, offset);

    return offset;
}

/* Unlock Trading Ack Message */
static unsigned
dissect_coinbasederivatives_ordersapi_unlock_trading_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_num_users_affected(tvb, pinfo, tree, offset);

    return offset;
}

/* Unlock Trading Reject Message */
static unsigned
dissect_coinbasederivatives_ordersapi_unlock_trading_reject(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_error_message(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Filled Message */
static unsigned
dissect_coinbasederivatives_ordersapi_order_filled(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_exec_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_match_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_client_order_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_order_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_filled_vwap(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_total_filled(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_available_qty(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_fill_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_fill_qty(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_is_aggressor(tvb, pinfo, tree, offset);

    return offset;
}

/* Spread Order Filled Message */
static unsigned
dissect_coinbasederivatives_ordersapi_spread_order_filled(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_exec_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_match_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_client_order_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_order_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_filled_vwap(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_total_filled(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_available_qty(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_fill_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_leg_1_fill_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_leg_2_fill_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_fill_qty(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_is_aggressor(tvb, pinfo, tree, offset);

    return offset;
}

/* Last Exec Id Request Message */
static unsigned
dissect_coinbasederivatives_ordersapi_last_exec_id_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);

    return offset;
}

/* Last Exec Id Message */
static unsigned
dissect_coinbasederivatives_ordersapi_last_exec_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_last_exec_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);

    return offset;
}

/* Event Resend Request Message */
static unsigned
dissect_coinbasederivatives_ordersapi_event_resend_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_begin_exec_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_end_exec_id(tvb, pinfo, tree, offset);

    return offset;
}

/* Event Resend Complete Message */
static unsigned
dissect_coinbasederivatives_ordersapi_event_resend_complete(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_resent_event_count(tvb, pinfo, tree, offset);

    return offset;
}

/* Event Resend Reject Message */
static unsigned
dissect_coinbasederivatives_ordersapi_event_resend_reject(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_resend_reject_reason(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_details_string_55(tvb, pinfo, tree, offset);

    return offset;
}

/* Reset Options Fill Protection Message */
static unsigned
dissect_coinbasederivatives_ordersapi_reset_options_fill_protection(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_product_id(tvb, pinfo, tree, offset);

    return offset;
}

/* Reset Options Fill Protection Ack Message */
static unsigned
dissect_coinbasederivatives_ordersapi_reset_options_fill_protection_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_product_id(tvb, pinfo, tree, offset);

    return offset;
}

/* Reset Options Fill Protection Reject Message */
static unsigned
dissect_coinbasederivatives_ordersapi_reset_options_fill_protection_reject(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_error_message(tvb, pinfo, tree, offset);

    return offset;
}

/* Session Message */
static unsigned
dissect_coinbasederivatives_ordersapi_session_v17(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;


    uint32_t template_id = tvb_get_letohs(tvb, start);

    offset = dissect_coinbasederivatives_ordersapi_session_payload_v17(tvb, pinfo, tree, offset, template_id);

    return offset;
}

/* Order Message */
static unsigned
dissect_coinbasederivatives_ordersapi_order_v17(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;


    uint32_t template_id = tvb_get_letohs(tvb, start);

    offset = dissect_coinbasederivatives_ordersapi_order_payload_v17(tvb, pinfo, tree, offset, template_id);

    return offset;
}

/* Logout Message V17 */
static unsigned
dissect_coinbasederivatives_ordersapi_logout_v17(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_reason(tvb, pinfo, tree, offset);

    return offset;
}

/* Logged Out Message V17 */
static unsigned
dissect_coinbasederivatives_ordersapi_logged_out_v17(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_reason(tvb, pinfo, tree, offset);

    return offset;
}

/* Session Message */
static unsigned
dissect_coinbasederivatives_ordersapi_session_v16(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;


    uint32_t template_id = tvb_get_letohs(tvb, start);

    offset = dissect_coinbasederivatives_ordersapi_session_payload_v16(tvb, pinfo, tree, offset, template_id);

    return offset;
}

/* Logout Message V16 */
static unsigned
dissect_coinbasederivatives_ordersapi_logout_v16(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_reason(tvb, pinfo, tree, offset);

    return offset;
}

/* Logged Out Message V16 */
static unsigned
dissect_coinbasederivatives_ordersapi_logged_out_v16(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_reason(tvb, pinfo, tree, offset);

    return offset;
}

/* Message Header */
static unsigned
dissect_coinbasederivatives_ordersapi_message_header_v15(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    proto_item *item = NULL;
    proto_tree *group = tree;

    if (coinbasederivatives_ordersapi_show_headers) {
        group = proto_tree_add_subtree(tree, tvb, offset, -1, ett_coinbasederivatives_ordersapi_message_header_v15, &item, "Message Header");
    }

    unsigned start = offset;

    offset = parse_coinbasederivatives_ordersapi_protocol_id(tvb, pinfo, group, offset);
    offset = parse_coinbasederivatives_ordersapi_flags_v15(tvb, pinfo, group, offset);
    offset = parse_coinbasederivatives_ordersapi_message_length(tvb, pinfo, group, offset);
    offset = parse_coinbasederivatives_ordersapi_sequence_number(tvb, pinfo, group, offset);
    offset = parse_coinbasederivatives_ordersapi_last_processed_seq_no(tvb, pinfo, group, offset);
    offset = parse_coinbasederivatives_ordersapi_reserved(tvb, pinfo, group, offset);
    offset = parse_coinbasederivatives_ordersapi_send_time_epoch_nanos(tvb, pinfo, group, offset);
    offset = parse_coinbasederivatives_ordersapi_block_length(tvb, pinfo, group, offset);
    offset = parse_coinbasederivatives_ordersapi_template_id(tvb, pinfo, group, offset);
    offset = parse_coinbasederivatives_ordersapi_schema_id(tvb, pinfo, group, offset);
    offset = parse_coinbasederivatives_ordersapi_version(tvb, pinfo, group, offset);

    proto_item_set_len(item, offset - start);

    return offset;
}

/* Session Message */
static unsigned
dissect_coinbasederivatives_ordersapi_session_v15(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;


    uint32_t template_id = tvb_get_letohs(tvb, start);

    offset = dissect_coinbasederivatives_ordersapi_session_payload_v15(tvb, pinfo, tree, offset, template_id);

    return offset;
}

/* Order Message */
static unsigned
dissect_coinbasederivatives_ordersapi_order_v15(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;


    uint32_t template_id = tvb_get_letohs(tvb, start);

    offset = dissect_coinbasederivatives_ordersapi_order_payload_v15(tvb, pinfo, tree, offset, template_id);

    return offset;
}

/* Logout Message V15 */
static unsigned
dissect_coinbasederivatives_ordersapi_logout_v15(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_reason(tvb, pinfo, tree, offset);

    return offset;
}

/* Logged Out Message V15 */
static unsigned
dissect_coinbasederivatives_ordersapi_logged_out_v15(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_reason(tvb, pinfo, tree, offset);

    return offset;
}

/* New Order Message V15 */
static unsigned
dissect_coinbasederivatives_ordersapi_new_order_v15(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_client_order_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_limit_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_quantity(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_side(tvb, pinfo, tree, offset);

    return offset;
}

/* Replace Order Message V15 */
static unsigned
dissect_coinbasederivatives_ordersapi_replace_order_v15(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_client_order_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_new_limit_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_new_quantity(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_instrument_id(tvb, pinfo, tree, offset);

    return offset;
}

/* Stream Order Message */
static unsigned
dissect_coinbasederivatives_ordersapi_stream_order(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_client_order_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_last_processed_fill_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_limit_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_quantity(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_side(tvb, pinfo, tree, offset);

    return offset;
}

/* Event Resend Reject Message V15 */
static unsigned
dissect_coinbasederivatives_ordersapi_event_resend_reject_v15(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_resend_reject_reason(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_event_resend_reject_details(tvb, pinfo, tree, offset);

    return offset;
}

/* Session Message */
static unsigned
dissect_coinbasederivatives_ordersapi_session_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;


    uint32_t template_id = tvb_get_letohs(tvb, start);

    offset = dissect_coinbasederivatives_ordersapi_session_payload_v14(tvb, pinfo, tree, offset, template_id);

    return offset;
}

/* Order Message */
static unsigned
dissect_coinbasederivatives_ordersapi_order_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;


    uint32_t template_id = tvb_get_letohs(tvb, start);

    offset = dissect_coinbasederivatives_ordersapi_order_payload_v14(tvb, pinfo, tree, offset, template_id);

    return offset;
}

/* Logout Message V14 */
static unsigned
dissect_coinbasederivatives_ordersapi_logout_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_reason(tvb, pinfo, tree, offset);

    return offset;
}

/* Logged Out Message V14 */
static unsigned
dissect_coinbasederivatives_ordersapi_logged_out_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_reason(tvb, pinfo, tree, offset);

    return offset;
}

/* New Order Message V14 */
static unsigned
dissect_coinbasederivatives_ordersapi_new_order_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_client_order_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_limit_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_quantity(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_side(tvb, pinfo, tree, offset);

    return offset;
}

/* Replace Order Message V14 */
static unsigned
dissect_coinbasederivatives_ordersapi_replace_order_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_client_order_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_new_limit_price(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_new_quantity(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_instrument_id(tvb, pinfo, tree, offset);

    return offset;
}

/* Event Resend Reject Message V14 */
static unsigned
dissect_coinbasederivatives_ordersapi_event_resend_reject_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_resend_reject_reason(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_event_resend_reject_details(tvb, pinfo, tree, offset);

    return offset;
}

/* Session Message */
static unsigned
dissect_coinbasederivatives_ordersapi_session_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;


    uint32_t template_id = tvb_get_letohs(tvb, start);

    offset = dissect_coinbasederivatives_ordersapi_session_payload_v13(tvb, pinfo, tree, offset, template_id);

    return offset;
}

/* Order Message */
static unsigned
dissect_coinbasederivatives_ordersapi_order_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    unsigned start = offset;


    uint32_t template_id = tvb_get_letohs(tvb, start);

    offset = dissect_coinbasederivatives_ordersapi_order_payload_v13(tvb, pinfo, tree, offset, template_id);

    return offset;
}

/* Logout Message V13 */
static unsigned
dissect_coinbasederivatives_ordersapi_logout_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_reason(tvb, pinfo, tree, offset);

    return offset;
}

/* Logged Out Message V13 */
static unsigned
dissect_coinbasederivatives_ordersapi_logged_out_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_reason(tvb, pinfo, tree, offset);

    return offset;
}

/* New Order Message V13 */
static unsigned
dissect_coinbasederivatives_ordersapi_new_order_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_client_order_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_limit_price_v13(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_quantity(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_side(tvb, pinfo, tree, offset);

    return offset;
}

/* Replace Order Message V13 */
static unsigned
dissect_coinbasederivatives_ordersapi_replace_order_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_client_order_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_new_limit_price_v13(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_new_quantity(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_instrument_id(tvb, pinfo, tree, offset);

    return offset;
}

/* Stream Order Message */
static unsigned
dissect_coinbasederivatives_ordersapi_stream_order_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_client_order_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_last_processed_fill_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_limit_price_v13(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_quantity(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_side(tvb, pinfo, tree, offset);

    return offset;
}

/* Mass Cancel Order Message */
static unsigned
dissect_coinbasederivatives_ordersapi_mass_cancel_order_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_limit_price_v13(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_side(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_current_session_only(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_request_trading_lock(tvb, pinfo, tree, offset);

    return offset;
}

/* Order Filled Message */
static unsigned
dissect_coinbasederivatives_ordersapi_order_filled_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_exec_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_match_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_client_order_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_order_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_filled_vwap_v13(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_total_filled(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_available_qty(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_fill_price_v13(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_fill_qty(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_is_aggressor(tvb, pinfo, tree, offset);

    return offset;
}

/* Spread Order Filled Message */
static unsigned
dissect_coinbasederivatives_ordersapi_spread_order_filled_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_timestamp(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_exec_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_match_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_client_order_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_order_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_filled_vwap_v13(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_total_filled(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_available_qty(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_fill_price_v13(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_leg_1_fill_price_v13(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_leg_2_fill_price_v13(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_fill_qty(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_instrument_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_is_aggressor(tvb, pinfo, tree, offset);

    return offset;
}

/* Event Resend Reject Message V13 */
static unsigned
dissect_coinbasederivatives_ordersapi_event_resend_reject_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset)
{
    offset = parse_coinbasederivatives_ordersapi_correlation_id(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_resend_reject_reason(tvb, pinfo, tree, offset);
    offset = parse_coinbasederivatives_ordersapi_event_resend_reject_details(tvb, pinfo, tree, offset);

    return offset;
}

/*
 * CoinbaseDerivatives OrdersApi Parse Trees, a dispatch per distinct branch definition
 */

static const value_string coinbasederivatives_ordersapi_messages[] = {
    { COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_SESSION, "Session Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_ORDER, "Order Message" },
    { 0, NULL }
};

/* Payload: dispatch on schema_id */
static unsigned
dissect_coinbasederivatives_ordersapi_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t schema_id)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, schema_id, coinbasederivatives_ordersapi_messages, "Unknown (%u)"));

    switch (schema_id) {
    case COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_SESSION:
        return dissect_coinbasederivatives_ordersapi_session(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_ORDER:
        return dissect_coinbasederivatives_ordersapi_order(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string coinbasederivatives_ordersapi_messages_v17[] = {
    { COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_SESSION, "Session Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_ORDER, "Order Message" },
    { 0, NULL }
};

/* Payload: dispatch on schema_id */
static unsigned
dissect_coinbasederivatives_ordersapi_payload_v17(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t schema_id)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, schema_id, coinbasederivatives_ordersapi_messages_v17, "Unknown (%u)"));

    switch (schema_id) {
    case COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_SESSION:
        return dissect_coinbasederivatives_ordersapi_session_v17(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_ORDER:
        return dissect_coinbasederivatives_ordersapi_order_v17(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string coinbasederivatives_ordersapi_messages_v16[] = {
    { COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_SESSION, "Session Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_ORDER, "Order Message" },
    { 0, NULL }
};

/* Payload: dispatch on schema_id */
static unsigned
dissect_coinbasederivatives_ordersapi_payload_v16(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t schema_id)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, schema_id, coinbasederivatives_ordersapi_messages_v16, "Unknown (%u)"));

    switch (schema_id) {
    case COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_SESSION:
        return dissect_coinbasederivatives_ordersapi_session_v16(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_ORDER:
        return dissect_coinbasederivatives_ordersapi_order_v17(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string coinbasederivatives_ordersapi_messages_v15[] = {
    { COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_SESSION, "Session Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_ORDER, "Order Message" },
    { 0, NULL }
};

/* Payload: dispatch on schema_id */
static unsigned
dissect_coinbasederivatives_ordersapi_payload_v15(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t schema_id)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, schema_id, coinbasederivatives_ordersapi_messages_v15, "Unknown (%u)"));

    switch (schema_id) {
    case COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_SESSION:
        return dissect_coinbasederivatives_ordersapi_session_v15(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_ORDER:
        return dissect_coinbasederivatives_ordersapi_order_v15(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string coinbasederivatives_ordersapi_messages_v14[] = {
    { COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_SESSION, "Session Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_ORDER, "Order Message" },
    { 0, NULL }
};

/* Payload: dispatch on schema_id */
static unsigned
dissect_coinbasederivatives_ordersapi_payload_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t schema_id)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, schema_id, coinbasederivatives_ordersapi_messages_v14, "Unknown (%u)"));

    switch (schema_id) {
    case COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_SESSION:
        return dissect_coinbasederivatives_ordersapi_session_v14(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_ORDER:
        return dissect_coinbasederivatives_ordersapi_order_v14(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string coinbasederivatives_ordersapi_messages_v13[] = {
    { COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_SESSION, "Session Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_ORDER, "Order Message" },
    { 0, NULL }
};

/* Payload: dispatch on schema_id */
static unsigned
dissect_coinbasederivatives_ordersapi_payload_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t schema_id)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, schema_id, coinbasederivatives_ordersapi_messages_v13, "Unknown (%u)"));

    switch (schema_id) {
    case COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_SESSION:
        return dissect_coinbasederivatives_ordersapi_session_v13(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_ORDER:
        return dissect_coinbasederivatives_ordersapi_order_v13(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string coinbasederivatives_ordersapi_session_payload_messages[] = {
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGON, "Logon Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGON_CONF, "Logon Conf Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGOUT, "Logout Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGGED_OUT, "Logged Out Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_HEARTBEAT, "Heartbeat Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_TEST_REQUEST, "Test Request Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_RESEND_REQUEST, "Resend Request Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_GAP_FILL, "Gap Fill Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_REJECT, "Reject Message" },
    { 0, NULL }
};

/* Session Payload: dispatch on template_id */
static unsigned
dissect_coinbasederivatives_ordersapi_session_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, template_id, coinbasederivatives_ordersapi_session_payload_messages, "Unknown (%u)"));

    switch (template_id) {
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGON:
        return dissect_coinbasederivatives_ordersapi_logon(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGON_CONF:
        return dissect_coinbasederivatives_ordersapi_logon_conf(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGOUT:
        return dissect_coinbasederivatives_ordersapi_logout(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGGED_OUT:
        return dissect_coinbasederivatives_ordersapi_logged_out(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_HEARTBEAT:
        return dissect_coinbasederivatives_ordersapi_heartbeat(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_TEST_REQUEST:
        return dissect_coinbasederivatives_ordersapi_test_request(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_RESEND_REQUEST:
        return dissect_coinbasederivatives_ordersapi_resend_request(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_GAP_FILL:
        return dissect_coinbasederivatives_ordersapi_gap_fill(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_REJECT:
        return dissect_coinbasederivatives_ordersapi_reject(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string coinbasederivatives_ordersapi_session_payload_messages_v17[] = {
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGON, "Logon Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGON_CONF, "Logon Conf Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGOUT, "Logout Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGGED_OUT, "Logged Out Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_HEARTBEAT, "Heartbeat Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_TEST_REQUEST, "Test Request Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_RESEND_REQUEST, "Resend Request Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_GAP_FILL, "Gap Fill Message" },
    { 0, NULL }
};

/* Session Payload: dispatch on template_id */
static unsigned
dissect_coinbasederivatives_ordersapi_session_payload_v17(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, template_id, coinbasederivatives_ordersapi_session_payload_messages_v17, "Unknown (%u)"));

    switch (template_id) {
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGON:
        return dissect_coinbasederivatives_ordersapi_logon(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGON_CONF:
        return dissect_coinbasederivatives_ordersapi_logon_conf(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGOUT:
        return dissect_coinbasederivatives_ordersapi_logout_v17(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGGED_OUT:
        return dissect_coinbasederivatives_ordersapi_logged_out_v17(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_HEARTBEAT:
        return dissect_coinbasederivatives_ordersapi_heartbeat(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_TEST_REQUEST:
        return dissect_coinbasederivatives_ordersapi_test_request(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_RESEND_REQUEST:
        return dissect_coinbasederivatives_ordersapi_resend_request(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_GAP_FILL:
        return dissect_coinbasederivatives_ordersapi_gap_fill(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string coinbasederivatives_ordersapi_session_payload_messages_v16[] = {
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGON, "Logon Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGON_CONF, "Logon Conf Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGOUT, "Logout Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGGED_OUT, "Logged Out Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_HEARTBEAT, "Heartbeat Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_TEST_REQUEST, "Test Request Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_RESEND_REQUEST, "Resend Request Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_GAP_FILL, "Gap Fill Message" },
    { 0, NULL }
};

/* Session Payload: dispatch on template_id */
static unsigned
dissect_coinbasederivatives_ordersapi_session_payload_v16(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, template_id, coinbasederivatives_ordersapi_session_payload_messages_v16, "Unknown (%u)"));

    switch (template_id) {
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGON:
        return dissect_coinbasederivatives_ordersapi_logon(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGON_CONF:
        return dissect_coinbasederivatives_ordersapi_logon_conf(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGOUT:
        return dissect_coinbasederivatives_ordersapi_logout_v16(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGGED_OUT:
        return dissect_coinbasederivatives_ordersapi_logged_out_v16(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_HEARTBEAT:
        return dissect_coinbasederivatives_ordersapi_heartbeat(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_TEST_REQUEST:
        return dissect_coinbasederivatives_ordersapi_test_request(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_RESEND_REQUEST:
        return dissect_coinbasederivatives_ordersapi_resend_request(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_GAP_FILL:
        return dissect_coinbasederivatives_ordersapi_gap_fill(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string coinbasederivatives_ordersapi_session_payload_messages_v15[] = {
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGON, "Logon Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGON_CONF, "Logon Conf Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGOUT, "Logout Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGGED_OUT, "Logged Out Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_HEARTBEAT, "Heartbeat Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_TEST_REQUEST, "Test Request Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_RESEND_REQUEST, "Resend Request Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_GAP_FILL, "Gap Fill Message" },
    { 0, NULL }
};

/* Session Payload: dispatch on template_id */
static unsigned
dissect_coinbasederivatives_ordersapi_session_payload_v15(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, template_id, coinbasederivatives_ordersapi_session_payload_messages_v15, "Unknown (%u)"));

    switch (template_id) {
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGON:
        return dissect_coinbasederivatives_ordersapi_logon(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGON_CONF:
        return dissect_coinbasederivatives_ordersapi_logon_conf(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGOUT:
        return dissect_coinbasederivatives_ordersapi_logout_v15(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGGED_OUT:
        return dissect_coinbasederivatives_ordersapi_logged_out_v15(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_HEARTBEAT:
        return dissect_coinbasederivatives_ordersapi_heartbeat(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_TEST_REQUEST:
        return dissect_coinbasederivatives_ordersapi_test_request(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_RESEND_REQUEST:
        return dissect_coinbasederivatives_ordersapi_resend_request(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_GAP_FILL:
        return dissect_coinbasederivatives_ordersapi_gap_fill(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string coinbasederivatives_ordersapi_session_payload_messages_v14[] = {
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGON, "Logon Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGON_CONF, "Logon Conf Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGOUT, "Logout Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGGED_OUT, "Logged Out Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_HEARTBEAT, "Heartbeat Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_TEST_REQUEST, "Test Request Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_RESEND_REQUEST, "Resend Request Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_GAP_FILL, "Gap Fill Message" },
    { 0, NULL }
};

/* Session Payload: dispatch on template_id */
static unsigned
dissect_coinbasederivatives_ordersapi_session_payload_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, template_id, coinbasederivatives_ordersapi_session_payload_messages_v14, "Unknown (%u)"));

    switch (template_id) {
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGON:
        return dissect_coinbasederivatives_ordersapi_logon(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGON_CONF:
        return dissect_coinbasederivatives_ordersapi_logon_conf(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGOUT:
        return dissect_coinbasederivatives_ordersapi_logout_v14(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGGED_OUT:
        return dissect_coinbasederivatives_ordersapi_logged_out_v14(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_HEARTBEAT:
        return dissect_coinbasederivatives_ordersapi_heartbeat(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_TEST_REQUEST:
        return dissect_coinbasederivatives_ordersapi_test_request(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_RESEND_REQUEST:
        return dissect_coinbasederivatives_ordersapi_resend_request(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_GAP_FILL:
        return dissect_coinbasederivatives_ordersapi_gap_fill(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string coinbasederivatives_ordersapi_session_payload_messages_v13[] = {
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGON, "Logon Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGON_CONF, "Logon Conf Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGOUT, "Logout Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGGED_OUT, "Logged Out Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_HEARTBEAT, "Heartbeat Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_TEST_REQUEST, "Test Request Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_RESEND_REQUEST, "Resend Request Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_GAP_FILL, "Gap Fill Message" },
    { 0, NULL }
};

/* Session Payload: dispatch on template_id */
static unsigned
dissect_coinbasederivatives_ordersapi_session_payload_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, template_id, coinbasederivatives_ordersapi_session_payload_messages_v13, "Unknown (%u)"));

    switch (template_id) {
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGON:
        return dissect_coinbasederivatives_ordersapi_logon(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGON_CONF:
        return dissect_coinbasederivatives_ordersapi_logon_conf(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGOUT:
        return dissect_coinbasederivatives_ordersapi_logout_v13(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_LOGGED_OUT:
        return dissect_coinbasederivatives_ordersapi_logged_out_v13(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_HEARTBEAT:
        return dissect_coinbasederivatives_ordersapi_heartbeat(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_TEST_REQUEST:
        return dissect_coinbasederivatives_ordersapi_test_request(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_RESEND_REQUEST:
        return dissect_coinbasederivatives_ordersapi_resend_request(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_GAP_FILL:
        return dissect_coinbasederivatives_ordersapi_gap_fill(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string coinbasederivatives_ordersapi_order_payload_messages[] = {
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_RESEND_REQUEST, "Ping Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_GAP_FILL, "Pong Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_INSTRUMENT_INFO_REQUEST, "Instrument Info Request Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_INSTRUMENT_INFO, "Instrument Info Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SET_ACCOUNT, "Set Account Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SET_TRADER, "Set Trader Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SET_ACK, "Set Ack Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_NEW_ORDER, "New Order Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_NEW_IOC_ORDER, "New Ioc Order Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_REJECT, "Order Entered Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_REPLACE_ORDER, "Replace Order Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_OBSOLETE_STREAM_ORDER, "Obsolete Stream Order Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_REJECT, "Order Reject Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_REPLACED, "Order Replaced Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER, "Cancel Order Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_CANCELED, "Order Canceled Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_REJECT, "Cancel Order Reject Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_ORDER, "Mass Cancel Order Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_ORDER_ACK, "Mass Cancel Order Ack Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_ORDER_REJECT, "Mass Cancel Order Reject Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_UNLOCK_TRADING, "Unlock Trading Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_UNLOCK_TRADING_ACK, "Unlock Trading Ack Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_UNLOCK_TRADING_REJECT, "Unlock Trading Reject Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_FILLED, "Order Filled Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SPREAD_ORDER_FILLED, "Spread Order Filled Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_LAST_EXEC_ID_REQUEST, "Last Exec Id Request Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_LAST_EXEC_ID, "Last Exec Id Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_EVENT_RESEND_REQUEST, "Event Resend Request Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_EVENT_RESEND_COMPLETE, "Event Resend Complete Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_EVENT_RESEND_REJECT, "Event Resend Reject Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_RESET_OPTIONS_FILL_PROTECTION, "Reset Options Fill Protection Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_RESET_OPTIONS_FILL_PROTECTION_ACK, "Reset Options Fill Protection Ack Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_RESET_OPTIONS_FILL_PROTECTION_REJECT, "Reset Options Fill Protection Reject Message" },
    { 0, NULL }
};

/* Order Payload: dispatch on template_id */
static unsigned
dissect_coinbasederivatives_ordersapi_order_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, template_id, coinbasederivatives_ordersapi_order_payload_messages, "Unknown (%u)"));

    switch (template_id) {
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_RESEND_REQUEST:
        return dissect_coinbasederivatives_ordersapi_ping(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_GAP_FILL:
        return dissect_coinbasederivatives_ordersapi_pong(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_INSTRUMENT_INFO_REQUEST:
        return dissect_coinbasederivatives_ordersapi_instrument_info_request(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_INSTRUMENT_INFO:
        return dissect_coinbasederivatives_ordersapi_instrument_info(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SET_ACCOUNT:
        return dissect_coinbasederivatives_ordersapi_set_account(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SET_TRADER:
        return dissect_coinbasederivatives_ordersapi_set_trader(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SET_ACK:
        return dissect_coinbasederivatives_ordersapi_set_ack(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_NEW_ORDER:
        return dissect_coinbasederivatives_ordersapi_new_order(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_NEW_IOC_ORDER:
        return dissect_coinbasederivatives_ordersapi_new_ioc_order(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_REJECT:
        return dissect_coinbasederivatives_ordersapi_order_entered(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_REPLACE_ORDER:
        return dissect_coinbasederivatives_ordersapi_replace_order(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_OBSOLETE_STREAM_ORDER:
        return dissect_coinbasederivatives_ordersapi_obsolete_stream_order(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_REJECT:
        return dissect_coinbasederivatives_ordersapi_order_reject(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_REPLACED:
        return dissect_coinbasederivatives_ordersapi_order_replaced(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER:
        return dissect_coinbasederivatives_ordersapi_cancel_order(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_CANCELED:
        return dissect_coinbasederivatives_ordersapi_order_canceled(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_REJECT:
        return dissect_coinbasederivatives_ordersapi_cancel_order_reject(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_ORDER:
        return dissect_coinbasederivatives_ordersapi_mass_cancel_order(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_ORDER_ACK:
        return dissect_coinbasederivatives_ordersapi_mass_cancel_order_ack(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_ORDER_REJECT:
        return dissect_coinbasederivatives_ordersapi_mass_cancel_order_reject(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_UNLOCK_TRADING:
        return dissect_coinbasederivatives_ordersapi_unlock_trading(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_UNLOCK_TRADING_ACK:
        return dissect_coinbasederivatives_ordersapi_unlock_trading_ack(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_UNLOCK_TRADING_REJECT:
        return dissect_coinbasederivatives_ordersapi_unlock_trading_reject(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_FILLED:
        return dissect_coinbasederivatives_ordersapi_order_filled(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SPREAD_ORDER_FILLED:
        return dissect_coinbasederivatives_ordersapi_spread_order_filled(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_LAST_EXEC_ID_REQUEST:
        return dissect_coinbasederivatives_ordersapi_last_exec_id_request(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_LAST_EXEC_ID:
        return dissect_coinbasederivatives_ordersapi_last_exec_id(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_EVENT_RESEND_REQUEST:
        return dissect_coinbasederivatives_ordersapi_event_resend_request(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_EVENT_RESEND_COMPLETE:
        return dissect_coinbasederivatives_ordersapi_event_resend_complete(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_EVENT_RESEND_REJECT:
        return dissect_coinbasederivatives_ordersapi_event_resend_reject(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_RESET_OPTIONS_FILL_PROTECTION:
        return dissect_coinbasederivatives_ordersapi_reset_options_fill_protection(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_RESET_OPTIONS_FILL_PROTECTION_ACK:
        return dissect_coinbasederivatives_ordersapi_reset_options_fill_protection_ack(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_RESET_OPTIONS_FILL_PROTECTION_REJECT:
        return dissect_coinbasederivatives_ordersapi_reset_options_fill_protection_reject(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string coinbasederivatives_ordersapi_order_payload_messages_v17[] = {
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_RESEND_REQUEST, "Ping Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_GAP_FILL, "Pong Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_INSTRUMENT_INFO_REQUEST, "Instrument Info Request Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_INSTRUMENT_INFO, "Instrument Info Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SET_ACCOUNT, "Set Account Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SET_TRADER, "Set Trader Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SET_ACK, "Set Ack Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_NEW_ORDER, "New Order Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_NEW_IOC_ORDER, "New Ioc Order Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_REJECT, "Order Entered Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_REPLACE_ORDER, "Replace Order Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_OBSOLETE_STREAM_ORDER, "Obsolete Stream Order Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_REJECT, "Order Reject Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_REPLACED, "Order Replaced Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER, "Cancel Order Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_CANCELED, "Order Canceled Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_REJECT, "Cancel Order Reject Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_ORDER, "Mass Cancel Order Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_ORDER_ACK, "Mass Cancel Order Ack Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_ORDER_REJECT, "Mass Cancel Order Reject Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_UNLOCK_TRADING, "Unlock Trading Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_UNLOCK_TRADING_ACK, "Unlock Trading Ack Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_UNLOCK_TRADING_REJECT, "Unlock Trading Reject Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_FILLED, "Order Filled Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SPREAD_ORDER_FILLED, "Spread Order Filled Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_LAST_EXEC_ID_REQUEST, "Last Exec Id Request Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_LAST_EXEC_ID, "Last Exec Id Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_EVENT_RESEND_REQUEST, "Event Resend Request Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_EVENT_RESEND_COMPLETE, "Event Resend Complete Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_EVENT_RESEND_REJECT, "Event Resend Reject Message" },
    { 0, NULL }
};

/* Order Payload: dispatch on template_id */
static unsigned
dissect_coinbasederivatives_ordersapi_order_payload_v17(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, template_id, coinbasederivatives_ordersapi_order_payload_messages_v17, "Unknown (%u)"));

    switch (template_id) {
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_RESEND_REQUEST:
        return dissect_coinbasederivatives_ordersapi_ping(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_GAP_FILL:
        return dissect_coinbasederivatives_ordersapi_pong(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_INSTRUMENT_INFO_REQUEST:
        return dissect_coinbasederivatives_ordersapi_instrument_info_request(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_INSTRUMENT_INFO:
        return dissect_coinbasederivatives_ordersapi_instrument_info(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SET_ACCOUNT:
        return dissect_coinbasederivatives_ordersapi_set_account(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SET_TRADER:
        return dissect_coinbasederivatives_ordersapi_set_trader(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SET_ACK:
        return dissect_coinbasederivatives_ordersapi_set_ack(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_NEW_ORDER:
        return dissect_coinbasederivatives_ordersapi_new_order(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_NEW_IOC_ORDER:
        return dissect_coinbasederivatives_ordersapi_new_ioc_order(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_REJECT:
        return dissect_coinbasederivatives_ordersapi_order_entered(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_REPLACE_ORDER:
        return dissect_coinbasederivatives_ordersapi_replace_order(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_OBSOLETE_STREAM_ORDER:
        return dissect_coinbasederivatives_ordersapi_obsolete_stream_order(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_REJECT:
        return dissect_coinbasederivatives_ordersapi_order_reject(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_REPLACED:
        return dissect_coinbasederivatives_ordersapi_order_replaced(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER:
        return dissect_coinbasederivatives_ordersapi_cancel_order(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_CANCELED:
        return dissect_coinbasederivatives_ordersapi_order_canceled(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_REJECT:
        return dissect_coinbasederivatives_ordersapi_cancel_order_reject(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_ORDER:
        return dissect_coinbasederivatives_ordersapi_mass_cancel_order(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_ORDER_ACK:
        return dissect_coinbasederivatives_ordersapi_mass_cancel_order_ack(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_ORDER_REJECT:
        return dissect_coinbasederivatives_ordersapi_mass_cancel_order_reject(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_UNLOCK_TRADING:
        return dissect_coinbasederivatives_ordersapi_unlock_trading(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_UNLOCK_TRADING_ACK:
        return dissect_coinbasederivatives_ordersapi_unlock_trading_ack(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_UNLOCK_TRADING_REJECT:
        return dissect_coinbasederivatives_ordersapi_unlock_trading_reject(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_FILLED:
        return dissect_coinbasederivatives_ordersapi_order_filled(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SPREAD_ORDER_FILLED:
        return dissect_coinbasederivatives_ordersapi_spread_order_filled(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_LAST_EXEC_ID_REQUEST:
        return dissect_coinbasederivatives_ordersapi_last_exec_id_request(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_LAST_EXEC_ID:
        return dissect_coinbasederivatives_ordersapi_last_exec_id(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_EVENT_RESEND_REQUEST:
        return dissect_coinbasederivatives_ordersapi_event_resend_request(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_EVENT_RESEND_COMPLETE:
        return dissect_coinbasederivatives_ordersapi_event_resend_complete(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_EVENT_RESEND_REJECT:
        return dissect_coinbasederivatives_ordersapi_event_resend_reject(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string coinbasederivatives_ordersapi_order_payload_messages_v15[] = {
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_RESEND_REQUEST, "Ping Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_GAP_FILL, "Pong Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_INSTRUMENT_INFO_REQUEST, "Instrument Info Request Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_INSTRUMENT_INFO, "Instrument Info Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SET_ACCOUNT, "Set Account Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SET_TRADER, "Set Trader Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SET_ACK, "Set Ack Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_NEW_ORDER, "New Order Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_REJECT, "Order Entered Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_REPLACE_ORDER, "Replace Order Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_OBSOLETE_STREAM_ORDER, "Stream Order Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_REJECT, "Order Reject Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_REPLACED, "Order Replaced Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER, "Cancel Order Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_CANCELED, "Order Canceled Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_REJECT, "Cancel Order Reject Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_ORDER, "Mass Cancel Order Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_ORDER_ACK, "Mass Cancel Order Ack Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_ORDER_REJECT, "Mass Cancel Order Reject Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_UNLOCK_TRADING, "Unlock Trading Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_UNLOCK_TRADING_ACK, "Unlock Trading Ack Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_UNLOCK_TRADING_REJECT, "Unlock Trading Reject Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_FILLED, "Order Filled Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SPREAD_ORDER_FILLED, "Spread Order Filled Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_LAST_EXEC_ID_REQUEST, "Last Exec Id Request Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_LAST_EXEC_ID, "Last Exec Id Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_EVENT_RESEND_REQUEST, "Event Resend Request Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_EVENT_RESEND_COMPLETE, "Event Resend Complete Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_EVENT_RESEND_REJECT, "Event Resend Reject Message" },
    { 0, NULL }
};

/* Order Payload: dispatch on template_id */
static unsigned
dissect_coinbasederivatives_ordersapi_order_payload_v15(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, template_id, coinbasederivatives_ordersapi_order_payload_messages_v15, "Unknown (%u)"));

    switch (template_id) {
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_RESEND_REQUEST:
        return dissect_coinbasederivatives_ordersapi_ping(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_GAP_FILL:
        return dissect_coinbasederivatives_ordersapi_pong(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_INSTRUMENT_INFO_REQUEST:
        return dissect_coinbasederivatives_ordersapi_instrument_info_request(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_INSTRUMENT_INFO:
        return dissect_coinbasederivatives_ordersapi_instrument_info(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SET_ACCOUNT:
        return dissect_coinbasederivatives_ordersapi_set_account(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SET_TRADER:
        return dissect_coinbasederivatives_ordersapi_set_trader(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SET_ACK:
        return dissect_coinbasederivatives_ordersapi_set_ack(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_NEW_ORDER:
        return dissect_coinbasederivatives_ordersapi_new_order_v15(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_REJECT:
        return dissect_coinbasederivatives_ordersapi_order_entered(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_REPLACE_ORDER:
        return dissect_coinbasederivatives_ordersapi_replace_order_v15(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_OBSOLETE_STREAM_ORDER:
        return dissect_coinbasederivatives_ordersapi_stream_order(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_REJECT:
        return dissect_coinbasederivatives_ordersapi_order_reject(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_REPLACED:
        return dissect_coinbasederivatives_ordersapi_order_replaced(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER:
        return dissect_coinbasederivatives_ordersapi_cancel_order(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_CANCELED:
        return dissect_coinbasederivatives_ordersapi_order_canceled(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_REJECT:
        return dissect_coinbasederivatives_ordersapi_cancel_order_reject(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_ORDER:
        return dissect_coinbasederivatives_ordersapi_mass_cancel_order(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_ORDER_ACK:
        return dissect_coinbasederivatives_ordersapi_mass_cancel_order_ack(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_ORDER_REJECT:
        return dissect_coinbasederivatives_ordersapi_mass_cancel_order_reject(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_UNLOCK_TRADING:
        return dissect_coinbasederivatives_ordersapi_unlock_trading(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_UNLOCK_TRADING_ACK:
        return dissect_coinbasederivatives_ordersapi_unlock_trading_ack(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_UNLOCK_TRADING_REJECT:
        return dissect_coinbasederivatives_ordersapi_unlock_trading_reject(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_FILLED:
        return dissect_coinbasederivatives_ordersapi_order_filled(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SPREAD_ORDER_FILLED:
        return dissect_coinbasederivatives_ordersapi_spread_order_filled(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_LAST_EXEC_ID_REQUEST:
        return dissect_coinbasederivatives_ordersapi_last_exec_id_request(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_LAST_EXEC_ID:
        return dissect_coinbasederivatives_ordersapi_last_exec_id(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_EVENT_RESEND_REQUEST:
        return dissect_coinbasederivatives_ordersapi_event_resend_request(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_EVENT_RESEND_COMPLETE:
        return dissect_coinbasederivatives_ordersapi_event_resend_complete(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_EVENT_RESEND_REJECT:
        return dissect_coinbasederivatives_ordersapi_event_resend_reject_v15(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string coinbasederivatives_ordersapi_order_payload_messages_v14[] = {
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_RESEND_REQUEST, "Ping Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_GAP_FILL, "Pong Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_INSTRUMENT_INFO_REQUEST, "Instrument Info Request Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_INSTRUMENT_INFO, "Instrument Info Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SET_ACCOUNT, "Set Account Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SET_TRADER, "Set Trader Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SET_ACK, "Set Ack Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_NEW_ORDER, "New Order Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_REJECT, "Order Entered Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_REPLACE_ORDER, "Replace Order Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_OBSOLETE_STREAM_ORDER, "Stream Order Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_REJECT, "Order Reject Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_REPLACED, "Order Replaced Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER, "Cancel Order Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_CANCELED, "Order Canceled Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_REJECT, "Cancel Order Reject Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_ORDER, "Mass Cancel Order Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_ORDER_ACK, "Mass Cancel Order Ack Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_ORDER_REJECT, "Mass Cancel Order Reject Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_UNLOCK_TRADING, "Unlock Trading Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_UNLOCK_TRADING_ACK, "Unlock Trading Ack Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_UNLOCK_TRADING_REJECT, "Unlock Trading Reject Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_FILLED, "Order Filled Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SPREAD_ORDER_FILLED, "Spread Order Filled Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_LAST_EXEC_ID_REQUEST, "Last Exec Id Request Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_LAST_EXEC_ID, "Last Exec Id Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_EVENT_RESEND_REQUEST, "Event Resend Request Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_EVENT_RESEND_COMPLETE, "Event Resend Complete Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_EVENT_RESEND_REJECT, "Event Resend Reject Message" },
    { 0, NULL }
};

/* Order Payload: dispatch on template_id */
static unsigned
dissect_coinbasederivatives_ordersapi_order_payload_v14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, template_id, coinbasederivatives_ordersapi_order_payload_messages_v14, "Unknown (%u)"));

    switch (template_id) {
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_RESEND_REQUEST:
        return dissect_coinbasederivatives_ordersapi_ping(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_GAP_FILL:
        return dissect_coinbasederivatives_ordersapi_pong(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_INSTRUMENT_INFO_REQUEST:
        return dissect_coinbasederivatives_ordersapi_instrument_info_request(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_INSTRUMENT_INFO:
        return dissect_coinbasederivatives_ordersapi_instrument_info(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SET_ACCOUNT:
        return dissect_coinbasederivatives_ordersapi_set_account(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SET_TRADER:
        return dissect_coinbasederivatives_ordersapi_set_trader(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SET_ACK:
        return dissect_coinbasederivatives_ordersapi_set_ack(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_NEW_ORDER:
        return dissect_coinbasederivatives_ordersapi_new_order_v14(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_REJECT:
        return dissect_coinbasederivatives_ordersapi_order_entered(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_REPLACE_ORDER:
        return dissect_coinbasederivatives_ordersapi_replace_order_v14(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_OBSOLETE_STREAM_ORDER:
        return dissect_coinbasederivatives_ordersapi_stream_order(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_REJECT:
        return dissect_coinbasederivatives_ordersapi_order_reject(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_REPLACED:
        return dissect_coinbasederivatives_ordersapi_order_replaced(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER:
        return dissect_coinbasederivatives_ordersapi_cancel_order(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_CANCELED:
        return dissect_coinbasederivatives_ordersapi_order_canceled(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_REJECT:
        return dissect_coinbasederivatives_ordersapi_cancel_order_reject(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_ORDER:
        return dissect_coinbasederivatives_ordersapi_mass_cancel_order(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_ORDER_ACK:
        return dissect_coinbasederivatives_ordersapi_mass_cancel_order_ack(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_ORDER_REJECT:
        return dissect_coinbasederivatives_ordersapi_mass_cancel_order_reject(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_UNLOCK_TRADING:
        return dissect_coinbasederivatives_ordersapi_unlock_trading(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_UNLOCK_TRADING_ACK:
        return dissect_coinbasederivatives_ordersapi_unlock_trading_ack(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_UNLOCK_TRADING_REJECT:
        return dissect_coinbasederivatives_ordersapi_unlock_trading_reject(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_FILLED:
        return dissect_coinbasederivatives_ordersapi_order_filled(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SPREAD_ORDER_FILLED:
        return dissect_coinbasederivatives_ordersapi_spread_order_filled(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_LAST_EXEC_ID_REQUEST:
        return dissect_coinbasederivatives_ordersapi_last_exec_id_request(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_LAST_EXEC_ID:
        return dissect_coinbasederivatives_ordersapi_last_exec_id(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_EVENT_RESEND_REQUEST:
        return dissect_coinbasederivatives_ordersapi_event_resend_request(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_EVENT_RESEND_COMPLETE:
        return dissect_coinbasederivatives_ordersapi_event_resend_complete(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_EVENT_RESEND_REJECT:
        return dissect_coinbasederivatives_ordersapi_event_resend_reject_v14(tvb, pinfo, tree, offset);
    }

    return offset;
}

static const value_string coinbasederivatives_ordersapi_order_payload_messages_v13[] = {
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_RESEND_REQUEST, "Ping Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_GAP_FILL, "Pong Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_INSTRUMENT_INFO_REQUEST, "Instrument Info Request Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_INSTRUMENT_INFO, "Instrument Info Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SET_ACCOUNT, "Set Account Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SET_TRADER, "Set Trader Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SET_ACK, "Set Ack Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_NEW_ORDER, "New Order Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_REJECT, "Order Entered Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_REPLACE_ORDER, "Replace Order Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_OBSOLETE_STREAM_ORDER, "Stream Order Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_REJECT, "Order Reject Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_REPLACED, "Order Replaced Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER, "Cancel Order Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_CANCELED, "Order Canceled Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_REJECT, "Cancel Order Reject Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_ORDER, "Mass Cancel Order Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_ORDER_ACK, "Mass Cancel Order Ack Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_ORDER_REJECT, "Mass Cancel Order Reject Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_UNLOCK_TRADING, "Unlock Trading Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_UNLOCK_TRADING_ACK, "Unlock Trading Ack Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_UNLOCK_TRADING_REJECT, "Unlock Trading Reject Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_FILLED, "Order Filled Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SPREAD_ORDER_FILLED, "Spread Order Filled Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_LAST_EXEC_ID_REQUEST, "Last Exec Id Request Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_LAST_EXEC_ID, "Last Exec Id Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_EVENT_RESEND_REQUEST, "Event Resend Request Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_EVENT_RESEND_COMPLETE, "Event Resend Complete Message" },
    { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_EVENT_RESEND_REJECT, "Event Resend Reject Message" },
    { 0, NULL }
};

/* Order Payload: dispatch on template_id */
static unsigned
dissect_coinbasederivatives_ordersapi_order_payload_v13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t template_id)
{
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", val_to_str(pinfo->pool, template_id, coinbasederivatives_ordersapi_order_payload_messages_v13, "Unknown (%u)"));

    switch (template_id) {
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_RESEND_REQUEST:
        return dissect_coinbasederivatives_ordersapi_ping(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SESSION_GAP_FILL:
        return dissect_coinbasederivatives_ordersapi_pong(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_INSTRUMENT_INFO_REQUEST:
        return dissect_coinbasederivatives_ordersapi_instrument_info_request(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_INSTRUMENT_INFO:
        return dissect_coinbasederivatives_ordersapi_instrument_info(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SET_ACCOUNT:
        return dissect_coinbasederivatives_ordersapi_set_account(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SET_TRADER:
        return dissect_coinbasederivatives_ordersapi_set_trader(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SET_ACK:
        return dissect_coinbasederivatives_ordersapi_set_ack(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_NEW_ORDER:
        return dissect_coinbasederivatives_ordersapi_new_order_v13(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_REJECT:
        return dissect_coinbasederivatives_ordersapi_order_entered(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_REPLACE_ORDER:
        return dissect_coinbasederivatives_ordersapi_replace_order_v13(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_OBSOLETE_STREAM_ORDER:
        return dissect_coinbasederivatives_ordersapi_stream_order_v13(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_REJECT:
        return dissect_coinbasederivatives_ordersapi_order_reject(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_REPLACED:
        return dissect_coinbasederivatives_ordersapi_order_replaced(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER:
        return dissect_coinbasederivatives_ordersapi_cancel_order(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_CANCELED:
        return dissect_coinbasederivatives_ordersapi_order_canceled(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_CANCEL_ORDER_REJECT:
        return dissect_coinbasederivatives_ordersapi_cancel_order_reject(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_ORDER:
        return dissect_coinbasederivatives_ordersapi_mass_cancel_order_v13(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_ORDER_ACK:
        return dissect_coinbasederivatives_ordersapi_mass_cancel_order_ack(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_MASS_CANCEL_ORDER_REJECT:
        return dissect_coinbasederivatives_ordersapi_mass_cancel_order_reject(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_UNLOCK_TRADING:
        return dissect_coinbasederivatives_ordersapi_unlock_trading(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_UNLOCK_TRADING_ACK:
        return dissect_coinbasederivatives_ordersapi_unlock_trading_ack(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_UNLOCK_TRADING_REJECT:
        return dissect_coinbasederivatives_ordersapi_unlock_trading_reject(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_ORDER_FILLED:
        return dissect_coinbasederivatives_ordersapi_order_filled_v13(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_SPREAD_ORDER_FILLED:
        return dissect_coinbasederivatives_ordersapi_spread_order_filled_v13(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_LAST_EXEC_ID_REQUEST:
        return dissect_coinbasederivatives_ordersapi_last_exec_id_request(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_LAST_EXEC_ID:
        return dissect_coinbasederivatives_ordersapi_last_exec_id(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_EVENT_RESEND_REQUEST:
        return dissect_coinbasederivatives_ordersapi_event_resend_request(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_EVENT_RESEND_COMPLETE:
        return dissect_coinbasederivatives_ordersapi_event_resend_complete(tvb, pinfo, tree, offset);
    case COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_EVENT_RESEND_REJECT:
        return dissect_coinbasederivatives_ordersapi_event_resend_reject_v13(tvb, pinfo, tree, offset);
    }

    return offset;
}

/* Show preference of the dispatched message */
static bool
coinbasederivatives_ordersapi_show(uint32_t schema_id)
{
    switch (schema_id) {
    case COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_SESSION:
        return coinbasederivatives_ordersapi_show_schema_messages;
    case COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_ORDER:
        return coinbasederivatives_ordersapi_show_schema_messages;
    }

    return true;
}

typedef struct coinbasederivatives_ordersapi_parse coinbasederivatives_ordersapi_parse;

struct coinbasederivatives_ordersapi_parse {
    const value_string *messages;
    unsigned (*dissect)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, uint32_t schema_id);
};

static const coinbasederivatives_ordersapi_parse coinbasederivatives_ordersapi_parse_v18 = { coinbasederivatives_ordersapi_messages, dissect_coinbasederivatives_ordersapi_payload };
static const coinbasederivatives_ordersapi_parse coinbasederivatives_ordersapi_parse_v17 = { coinbasederivatives_ordersapi_messages_v17, dissect_coinbasederivatives_ordersapi_payload_v17 };
static const coinbasederivatives_ordersapi_parse coinbasederivatives_ordersapi_parse_v16 = { coinbasederivatives_ordersapi_messages_v16, dissect_coinbasederivatives_ordersapi_payload_v16 };
static const coinbasederivatives_ordersapi_parse coinbasederivatives_ordersapi_parse_v15 = { coinbasederivatives_ordersapi_messages_v15, dissect_coinbasederivatives_ordersapi_payload_v15 };
static const coinbasederivatives_ordersapi_parse coinbasederivatives_ordersapi_parse_v14 = { coinbasederivatives_ordersapi_messages_v14, dissect_coinbasederivatives_ordersapi_payload_v14 };
static const coinbasederivatives_ordersapi_parse coinbasederivatives_ordersapi_parse_v13 = { coinbasederivatives_ordersapi_messages_v13, dissect_coinbasederivatives_ordersapi_payload_v13 };

/* Parse tree of the selected version */
static const coinbasederivatives_ordersapi_parse *
coinbasederivatives_ordersapi_parse_for(int version)
{
    switch (version) {
    case COINBASEDERIVATIVES_ORDERSAPI_VERSION_1_7:
        return &coinbasederivatives_ordersapi_parse_v17;
    case COINBASEDERIVATIVES_ORDERSAPI_VERSION_1_6:
        return &coinbasederivatives_ordersapi_parse_v16;
    case COINBASEDERIVATIVES_ORDERSAPI_VERSION_1_5:
        return &coinbasederivatives_ordersapi_parse_v15;
    case COINBASEDERIVATIVES_ORDERSAPI_VERSION_1_4:
        return &coinbasederivatives_ordersapi_parse_v14;
    case COINBASEDERIVATIVES_ORDERSAPI_VERSION_1_3:
        return &coinbasederivatives_ordersapi_parse_v13;
    default:
        return &coinbasederivatives_ordersapi_parse_v18;
    }
}

/* One length prefixed message, returns the consumed size */
static unsigned
dissect_coinbasederivatives_ordersapi_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, const coinbasederivatives_ordersapi_parse *parse)
{
    uint32_t message_length = tvb_get_letohs(tvb, offset + 2);
    uint32_t schema_id = tvb_get_letohs(tvb, offset + 28);

    const char *name = val_to_str(pinfo->pool, schema_id, parse->messages, "Unknown (%u)");

    proto_tree *message = coinbasederivatives_ordersapi_show(schema_id)
        ? proto_tree_add_subtree(tree, tvb, offset, message_length, ett_coinbasederivatives_ordersapi_message, NULL, name)
        : tree;

    unsigned position = offset;

    position = dissect_coinbasederivatives_ordersapi_message_header(tvb, pinfo, message, position);

    position = parse->dissect(tvb, pinfo, message, position, schema_id);

    /* Padding: Tcp sbe alignment padding */
    uint32_t padding = message_length - (uint32_t)(position - offset);

    if (padding > 0) {
        proto_tree_add_item(message, hf_coinbasederivatives_ordersapi_padding, tvb, position, padding, COINBASEDERIVATIVES_ORDERSAPI_PADDING_ENCODING);
        position += padding;
    }

    /* The parsed fields must account for the declared length exactly */
    if (position != offset + message_length) {
        expert_add_info(pinfo, message, &ei_coinbasederivatives_ordersapi_length);
    }

    return message_length;
}

/* Framed messages to the end of the stream, a partial
   frame asks the transport for its remaining bytes */
static unsigned
dissect_coinbasederivatives_ordersapi_messages(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned offset, const coinbasederivatives_ordersapi_parse *parse)
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

        offset += dissect_coinbasederivatives_ordersapi_message(tvb, pinfo, tree, offset, parse);
    }

    return offset;
}

/* Packet: header then counted messages */
static int
dissect_coinbasederivatives_ordersapi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, COINBASEDERIVATIVES_ORDERSAPI_PROTOCOL_SHORT);
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *item = proto_tree_add_item(tree, proto_coinbasederivatives_ordersapi, tvb, 0, -1, ENC_NA);
    proto_tree *packet = proto_item_add_subtree(item, ett_coinbasederivatives_ordersapi);

    uint64_t seconds = (uint64_t)pinfo->abs_ts.secs;
    int version = coinbasederivatives_ordersapi_version(seconds);

    proto_item_append_text(item, " %s", coinbasederivatives_ordersapi_version_name(version));

    const coinbasederivatives_ordersapi_parse *parse = coinbasederivatives_ordersapi_parse_for(version);
    unsigned position = 0;

    position = dissect_coinbasederivatives_ordersapi_messages(tvb, pinfo, packet, position, parse);

    return (int)position;
}

/* The fewest bytes any frame of the protocol holds, a header without messages */
#define COINBASEDERIVATIVES_ORDERSAPI_MINIMUM_SIZE 32

/* Version, each value a version pins it to */
static bool
coinbasederivatives_ordersapi_heur_identifier(tvbuff_t *tvb)
{
    switch (tvb_get_letohs(tvb, 30)) {
    case 0x0002: /* Version 1.2, 1.8 */
    case 0x0000: /* Version 0.1, 1.7, 1.6, 1.5, 1.4, 1.3 */
        return true;
    default:
        return false;
    }
}

/* The first frame's declared length fits the stream */
static bool
coinbasederivatives_ordersapi_heur_frame(tvbuff_t *tvb)
{
    int frame = (int)(tvb_get_letohs(tvb, 2));

    return frame >= COINBASEDERIVATIVES_ORDERSAPI_HEADER_SIZE && frame <= (int)tvb_reported_length(tvb);
}

/* Does the frame pass every test of Packet? */
static bool
coinbasederivatives_ordersapi_heur_accepts(tvbuff_t *tvb, packet_info *pinfo _U_)
{
    if (!coinbasederivatives_ordersapi_heur_identifier(tvb)) {
        return false;
    }

    if (!coinbasederivatives_ordersapi_heur_frame(tvb)) {
        return false;
    }

    return true;
}

/* Recognize the protocol by content */
static bool
dissect_coinbasederivatives_ordersapi_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (tvb_captured_length(tvb) < COINBASEDERIVATIVES_ORDERSAPI_MINIMUM_SIZE) {
        return false;
    }

    if (!coinbasederivatives_ordersapi_heur_accepts(tvb, pinfo)) {
        return false;
    }

    dissect_coinbasederivatives_ordersapi(tvb, pinfo, tree, data);

    return true;
}

/*
 * CoinbaseDerivatives OrdersApi Registration
 */

void
proto_register_coinbasederivatives_ordersapi(void)
{
    static hf_register_info hf[] = {

        /* Fields */
        { &hf_coinbasederivatives_ordersapi_account,
            { COINBASEDERIVATIVES_ORDERSAPI_ACCOUNT_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_ACCOUNT_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_ACCOUNT_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_ACCOUNT_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_ACCOUNT_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_ACCOUNT_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_available_qty,
            { COINBASEDERIVATIVES_ORDERSAPI_AVAILABLE_QTY_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_AVAILABLE_QTY_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_AVAILABLE_QTY_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_AVAILABLE_QTY_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_AVAILABLE_QTY_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_AVAILABLE_QTY_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_begin_exec_id,
            { COINBASEDERIVATIVES_ORDERSAPI_BEGIN_EXEC_ID_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_BEGIN_EXEC_ID_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_BEGIN_EXEC_ID_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_BEGIN_EXEC_ID_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_BEGIN_EXEC_ID_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_BEGIN_EXEC_ID_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_block_length,
            { COINBASEDERIVATIVES_ORDERSAPI_BLOCK_LENGTH_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_BLOCK_LENGTH_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_BLOCK_LENGTH_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_BLOCK_LENGTH_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_BLOCK_LENGTH_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_BLOCK_LENGTH_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_cancel_order_reject_details,
            { COINBASEDERIVATIVES_ORDERSAPI_CANCEL_ORDER_REJECT_DETAILS_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_CANCEL_ORDER_REJECT_DETAILS_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_CANCEL_ORDER_REJECT_DETAILS_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_CANCEL_ORDER_REJECT_DETAILS_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_CANCEL_ORDER_REJECT_DETAILS_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_CANCEL_ORDER_REJECT_DETAILS_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_cancel_order_reject_reason,
            { COINBASEDERIVATIVES_ORDERSAPI_CANCEL_ORDER_REJECT_REASON_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_CANCEL_ORDER_REJECT_REASON_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_CANCEL_ORDER_REJECT_REASON_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_CANCEL_ORDER_REJECT_REASON_DISPLAY,
              VALS(coinbasederivatives_ordersapi_cancel_order_reject_reason_vals),
              COINBASEDERIVATIVES_ORDERSAPI_CANCEL_ORDER_REJECT_REASON_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_CANCEL_ORDER_REJECT_REASON_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_cancel_reason,
            { COINBASEDERIVATIVES_ORDERSAPI_CANCEL_REASON_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_CANCEL_REASON_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_CANCEL_REASON_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_CANCEL_REASON_DISPLAY,
              VALS(coinbasederivatives_ordersapi_cancel_reason_vals),
              COINBASEDERIVATIVES_ORDERSAPI_CANCEL_REASON_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_CANCEL_REASON_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_canceled_count,
            { COINBASEDERIVATIVES_ORDERSAPI_CANCELED_COUNT_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_CANCELED_COUNT_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_CANCELED_COUNT_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_CANCELED_COUNT_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_CANCELED_COUNT_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_CANCELED_COUNT_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_client_order_id,
            { COINBASEDERIVATIVES_ORDERSAPI_CLIENT_ORDER_ID_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_CLIENT_ORDER_ID_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_CLIENT_ORDER_ID_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_CLIENT_ORDER_ID_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_CLIENT_ORDER_ID_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_CLIENT_ORDER_ID_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_correlation_id,
            { COINBASEDERIVATIVES_ORDERSAPI_CORRELATION_ID_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_CORRELATION_ID_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_CORRELATION_ID_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_CORRELATION_ID_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_CORRELATION_ID_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_CORRELATION_ID_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_current_session_only,
            { COINBASEDERIVATIVES_ORDERSAPI_CURRENT_SESSION_ONLY_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_CURRENT_SESSION_ONLY_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_CURRENT_SESSION_ONLY_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_CURRENT_SESSION_ONLY_DISPLAY,
              VALS(coinbasederivatives_ordersapi_current_session_only_vals),
              COINBASEDERIVATIVES_ORDERSAPI_CURRENT_SESSION_ONLY_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_CURRENT_SESSION_ONLY_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_data_length,
            { COINBASEDERIVATIVES_ORDERSAPI_DATA_LENGTH_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_DATA_LENGTH_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_DATA_LENGTH_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_DATA_LENGTH_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_DATA_LENGTH_MASK,
              NULL,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_data_value,
            { COINBASEDERIVATIVES_ORDERSAPI_DATA_VALUE_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_DATA_VALUE_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_DATA_VALUE_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_DATA_VALUE_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_DATA_VALUE_MASK,
              NULL,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_details,
            { COINBASEDERIVATIVES_ORDERSAPI_DETAILS_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_DETAILS_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_DETAILS_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_DETAILS_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_DETAILS_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_DETAILS_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_details_string_55,
            { COINBASEDERIVATIVES_ORDERSAPI_DETAILS_STRING_55_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_DETAILS_STRING_55_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_DETAILS_STRING_55_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_DETAILS_STRING_55_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_DETAILS_STRING_55_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_DETAILS_STRING_55_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_end_exec_id,
            { COINBASEDERIVATIVES_ORDERSAPI_END_EXEC_ID_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_END_EXEC_ID_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_END_EXEC_ID_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_END_EXEC_ID_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_END_EXEC_ID_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_END_EXEC_ID_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_error_message,
            { COINBASEDERIVATIVES_ORDERSAPI_ERROR_MESSAGE_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_ERROR_MESSAGE_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_ERROR_MESSAGE_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_ERROR_MESSAGE_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_ERROR_MESSAGE_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_ERROR_MESSAGE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_event_resend_reject_details,
            { COINBASEDERIVATIVES_ORDERSAPI_EVENT_RESEND_REJECT_DETAILS_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_EVENT_RESEND_REJECT_DETAILS_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_EVENT_RESEND_REJECT_DETAILS_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_EVENT_RESEND_REJECT_DETAILS_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_EVENT_RESEND_REJECT_DETAILS_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_EVENT_RESEND_REJECT_DETAILS_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_exec_id,
            { COINBASEDERIVATIVES_ORDERSAPI_EXEC_ID_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_EXEC_ID_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_EXEC_ID_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_EXEC_ID_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_EXEC_ID_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_EXEC_ID_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_fill_price,
            { COINBASEDERIVATIVES_ORDERSAPI_FILL_PRICE_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_FILL_PRICE_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_FILL_PRICE_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_FILL_PRICE_DISPLAY,
              CF_FUNC(coinbasederivatives_ordersapi_format_decimal_9_64),
              COINBASEDERIVATIVES_ORDERSAPI_FILL_PRICE_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_FILL_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_fill_price_v13,
            { COINBASEDERIVATIVES_ORDERSAPI_FILL_PRICE_V13_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_FILL_PRICE_V13_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_FILL_PRICE_V13_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_FILL_PRICE_V13_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_FILL_PRICE_V13_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_FILL_PRICE_V13_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_fill_qty,
            { COINBASEDERIVATIVES_ORDERSAPI_FILL_QTY_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_FILL_QTY_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_FILL_QTY_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_FILL_QTY_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_FILL_QTY_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_FILL_QTY_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_filled_vwap,
            { COINBASEDERIVATIVES_ORDERSAPI_FILLED_VWAP_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_FILLED_VWAP_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_FILLED_VWAP_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_FILLED_VWAP_DISPLAY,
              CF_FUNC(coinbasederivatives_ordersapi_format_decimal_9_64),
              COINBASEDERIVATIVES_ORDERSAPI_FILLED_VWAP_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_FILLED_VWAP_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_filled_vwap_v13,
            { COINBASEDERIVATIVES_ORDERSAPI_FILLED_VWAP_V13_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_FILLED_VWAP_V13_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_FILLED_VWAP_V13_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_FILLED_VWAP_V13_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_FILLED_VWAP_V13_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_FILLED_VWAP_V13_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_from_sequence_number,
            { COINBASEDERIVATIVES_ORDERSAPI_FROM_SEQUENCE_NUMBER_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_FROM_SEQUENCE_NUMBER_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_FROM_SEQUENCE_NUMBER_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_FROM_SEQUENCE_NUMBER_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_FROM_SEQUENCE_NUMBER_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_FROM_SEQUENCE_NUMBER_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_gap_fill_padding,
            { COINBASEDERIVATIVES_ORDERSAPI_GAP_FILL_PADDING_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_GAP_FILL_PADDING_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_GAP_FILL_PADDING_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_GAP_FILL_PADDING_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_GAP_FILL_PADDING_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_GAP_FILL_PADDING_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_good_til_date,
            { COINBASEDERIVATIVES_ORDERSAPI_GOOD_TIL_DATE_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_GOOD_TIL_DATE_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_GOOD_TIL_DATE_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_GOOD_TIL_DATE_DISPLAY,
              CF_FUNC(coinbasederivatives_ordersapi_format_nullable_32),
              COINBASEDERIVATIVES_ORDERSAPI_GOOD_TIL_DATE_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_GOOD_TIL_DATE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_heartbeat_interval_seconds,
            { COINBASEDERIVATIVES_ORDERSAPI_HEARTBEAT_INTERVAL_SECONDS_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_HEARTBEAT_INTERVAL_SECONDS_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_HEARTBEAT_INTERVAL_SECONDS_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_HEARTBEAT_INTERVAL_SECONDS_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_HEARTBEAT_INTERVAL_SECONDS_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_HEARTBEAT_INTERVAL_SECONDS_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_instrument_id,
            { COINBASEDERIVATIVES_ORDERSAPI_INSTRUMENT_ID_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_INSTRUMENT_ID_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_INSTRUMENT_ID_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_INSTRUMENT_ID_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_INSTRUMENT_ID_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_INSTRUMENT_ID_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_instrument_status,
            { COINBASEDERIVATIVES_ORDERSAPI_INSTRUMENT_STATUS_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_INSTRUMENT_STATUS_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_INSTRUMENT_STATUS_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_INSTRUMENT_STATUS_DISPLAY,
              VALS(coinbasederivatives_ordersapi_instrument_status_vals),
              COINBASEDERIVATIVES_ORDERSAPI_INSTRUMENT_STATUS_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_INSTRUMENT_STATUS_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_is_aggressor,
            { COINBASEDERIVATIVES_ORDERSAPI_IS_AGGRESSOR_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_IS_AGGRESSOR_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_IS_AGGRESSOR_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_IS_AGGRESSOR_DISPLAY,
              VALS(coinbasederivatives_ordersapi_is_aggressor_vals),
              COINBASEDERIVATIVES_ORDERSAPI_IS_AGGRESSOR_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_IS_AGGRESSOR_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_is_last_message,
            { COINBASEDERIVATIVES_ORDERSAPI_IS_LAST_MESSAGE_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_IS_LAST_MESSAGE_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_IS_LAST_MESSAGE_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_IS_LAST_MESSAGE_DISPLAY,
              VALS(coinbasederivatives_ordersapi_is_last_message_vals),
              COINBASEDERIVATIVES_ORDERSAPI_IS_LAST_MESSAGE_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_IS_LAST_MESSAGE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_last_exec_id,
            { COINBASEDERIVATIVES_ORDERSAPI_LAST_EXEC_ID_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_LAST_EXEC_ID_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_LAST_EXEC_ID_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_LAST_EXEC_ID_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_LAST_EXEC_ID_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_LAST_EXEC_ID_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_last_processed_fill_id,
            { COINBASEDERIVATIVES_ORDERSAPI_LAST_PROCESSED_FILL_ID_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_LAST_PROCESSED_FILL_ID_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_LAST_PROCESSED_FILL_ID_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_LAST_PROCESSED_FILL_ID_DISPLAY,
              CF_FUNC(coinbasederivatives_ordersapi_format_nullable_64),
              COINBASEDERIVATIVES_ORDERSAPI_LAST_PROCESSED_FILL_ID_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_LAST_PROCESSED_FILL_ID_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_last_processed_seq_no,
            { COINBASEDERIVATIVES_ORDERSAPI_LAST_PROCESSED_SEQ_NO_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_LAST_PROCESSED_SEQ_NO_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_LAST_PROCESSED_SEQ_NO_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_LAST_PROCESSED_SEQ_NO_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_LAST_PROCESSED_SEQ_NO_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_LAST_PROCESSED_SEQ_NO_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_leg_1_fill_price,
            { COINBASEDERIVATIVES_ORDERSAPI_LEG_1_FILL_PRICE_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_LEG_1_FILL_PRICE_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_LEG_1_FILL_PRICE_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_LEG_1_FILL_PRICE_DISPLAY,
              CF_FUNC(coinbasederivatives_ordersapi_format_decimal_9_64),
              COINBASEDERIVATIVES_ORDERSAPI_LEG_1_FILL_PRICE_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_LEG_1_FILL_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_leg_1_fill_price_v13,
            { COINBASEDERIVATIVES_ORDERSAPI_LEG_1_FILL_PRICE_V13_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_LEG_1_FILL_PRICE_V13_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_LEG_1_FILL_PRICE_V13_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_LEG_1_FILL_PRICE_V13_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_LEG_1_FILL_PRICE_V13_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_LEG_1_FILL_PRICE_V13_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_leg_2_fill_price,
            { COINBASEDERIVATIVES_ORDERSAPI_LEG_2_FILL_PRICE_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_LEG_2_FILL_PRICE_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_LEG_2_FILL_PRICE_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_LEG_2_FILL_PRICE_DISPLAY,
              CF_FUNC(coinbasederivatives_ordersapi_format_decimal_9_64),
              COINBASEDERIVATIVES_ORDERSAPI_LEG_2_FILL_PRICE_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_LEG_2_FILL_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_leg_2_fill_price_v13,
            { COINBASEDERIVATIVES_ORDERSAPI_LEG_2_FILL_PRICE_V13_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_LEG_2_FILL_PRICE_V13_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_LEG_2_FILL_PRICE_V13_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_LEG_2_FILL_PRICE_V13_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_LEG_2_FILL_PRICE_V13_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_LEG_2_FILL_PRICE_V13_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_limit_price,
            { COINBASEDERIVATIVES_ORDERSAPI_LIMIT_PRICE_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_LIMIT_PRICE_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_LIMIT_PRICE_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_LIMIT_PRICE_DISPLAY,
              CF_FUNC(coinbasederivatives_ordersapi_format_decimal_9_64),
              COINBASEDERIVATIVES_ORDERSAPI_LIMIT_PRICE_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_LIMIT_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_limit_price_v13,
            { COINBASEDERIVATIVES_ORDERSAPI_LIMIT_PRICE_V13_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_LIMIT_PRICE_V13_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_LIMIT_PRICE_V13_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_LIMIT_PRICE_V13_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_LIMIT_PRICE_V13_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_LIMIT_PRICE_V13_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_match_id,
            { COINBASEDERIVATIVES_ORDERSAPI_MATCH_ID_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_MATCH_ID_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_MATCH_ID_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_MATCH_ID_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_MATCH_ID_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_MATCH_ID_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_message_length,
            { COINBASEDERIVATIVES_ORDERSAPI_MESSAGE_LENGTH_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_MESSAGE_LENGTH_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_MESSAGE_LENGTH_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_MESSAGE_LENGTH_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_MESSAGE_LENGTH_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_MESSAGE_LENGTH_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_min_qty,
            { COINBASEDERIVATIVES_ORDERSAPI_MIN_QTY_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_MIN_QTY_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_MIN_QTY_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_MIN_QTY_DISPLAY,
              CF_FUNC(coinbasederivatives_ordersapi_format_nullable_32),
              COINBASEDERIVATIVES_ORDERSAPI_MIN_QTY_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_MIN_QTY_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_new_limit_price,
            { COINBASEDERIVATIVES_ORDERSAPI_NEW_LIMIT_PRICE_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_NEW_LIMIT_PRICE_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_NEW_LIMIT_PRICE_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_NEW_LIMIT_PRICE_DISPLAY,
              CF_FUNC(coinbasederivatives_ordersapi_format_decimal_9_64_nullable),
              COINBASEDERIVATIVES_ORDERSAPI_NEW_LIMIT_PRICE_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_NEW_LIMIT_PRICE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_new_limit_price_v13,
            { COINBASEDERIVATIVES_ORDERSAPI_NEW_LIMIT_PRICE_V13_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_NEW_LIMIT_PRICE_V13_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_NEW_LIMIT_PRICE_V13_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_NEW_LIMIT_PRICE_V13_DISPLAY,
              CF_FUNC(coinbasederivatives_ordersapi_format_nullable_64),
              COINBASEDERIVATIVES_ORDERSAPI_NEW_LIMIT_PRICE_V13_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_NEW_LIMIT_PRICE_V13_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_new_quantity,
            { COINBASEDERIVATIVES_ORDERSAPI_NEW_QUANTITY_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_NEW_QUANTITY_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_NEW_QUANTITY_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_NEW_QUANTITY_DISPLAY,
              CF_FUNC(coinbasederivatives_ordersapi_format_nullable_32),
              COINBASEDERIVATIVES_ORDERSAPI_NEW_QUANTITY_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_NEW_QUANTITY_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_new_sequence_number,
            { COINBASEDERIVATIVES_ORDERSAPI_NEW_SEQUENCE_NUMBER_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_NEW_SEQUENCE_NUMBER_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_NEW_SEQUENCE_NUMBER_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_NEW_SEQUENCE_NUMBER_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_NEW_SEQUENCE_NUMBER_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_NEW_SEQUENCE_NUMBER_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_num_users_affected,
            { COINBASEDERIVATIVES_ORDERSAPI_NUM_USERS_AFFECTED_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_NUM_USERS_AFFECTED_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_NUM_USERS_AFFECTED_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_NUM_USERS_AFFECTED_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_NUM_USERS_AFFECTED_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_NUM_USERS_AFFECTED_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_only_current_session,
            { COINBASEDERIVATIVES_ORDERSAPI_ONLY_CURRENT_SESSION_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_ONLY_CURRENT_SESSION_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_ONLY_CURRENT_SESSION_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_ONLY_CURRENT_SESSION_DISPLAY,
              VALS(coinbasederivatives_ordersapi_only_current_session_vals),
              COINBASEDERIVATIVES_ORDERSAPI_ONLY_CURRENT_SESSION_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_ONLY_CURRENT_SESSION_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_order_id,
            { COINBASEDERIVATIVES_ORDERSAPI_ORDER_ID_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_ORDER_ID_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_ORDER_ID_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_ORDER_ID_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_ORDER_ID_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_ORDER_ID_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_order_id_optional,
            { COINBASEDERIVATIVES_ORDERSAPI_ORDER_ID_OPTIONAL_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_ORDER_ID_OPTIONAL_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_ORDER_ID_OPTIONAL_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_ORDER_ID_OPTIONAL_DISPLAY,
              CF_FUNC(coinbasederivatives_ordersapi_format_nullable_64),
              COINBASEDERIVATIVES_ORDERSAPI_ORDER_ID_OPTIONAL_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_ORDER_ID_OPTIONAL_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_order_reject_details,
            { COINBASEDERIVATIVES_ORDERSAPI_ORDER_REJECT_DETAILS_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_ORDER_REJECT_DETAILS_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_ORDER_REJECT_DETAILS_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_ORDER_REJECT_DETAILS_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_ORDER_REJECT_DETAILS_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_ORDER_REJECT_DETAILS_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_order_reject_reason,
            { COINBASEDERIVATIVES_ORDERSAPI_ORDER_REJECT_REASON_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_ORDER_REJECT_REASON_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_ORDER_REJECT_REASON_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_ORDER_REJECT_REASON_DISPLAY,
              VALS(coinbasederivatives_ordersapi_order_reject_reason_vals),
              COINBASEDERIVATIVES_ORDERSAPI_ORDER_REJECT_REASON_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_ORDER_REJECT_REASON_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_padding,
            { COINBASEDERIVATIVES_ORDERSAPI_PADDING_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_PADDING_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_PADDING_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_PADDING_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_PADDING_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_PADDING_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_password,
            { COINBASEDERIVATIVES_ORDERSAPI_PASSWORD_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_PASSWORD_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_PASSWORD_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_PASSWORD_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_PASSWORD_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_PASSWORD_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_product_id,
            { COINBASEDERIVATIVES_ORDERSAPI_PRODUCT_ID_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_PRODUCT_ID_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_PRODUCT_ID_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_PRODUCT_ID_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_PRODUCT_ID_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_PRODUCT_ID_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_protocol_id,
            { COINBASEDERIVATIVES_ORDERSAPI_PROTOCOL_ID_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_PROTOCOL_ID_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_PROTOCOL_ID_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_PROTOCOL_ID_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_PROTOCOL_ID_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_PROTOCOL_ID_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_quantity,
            { COINBASEDERIVATIVES_ORDERSAPI_QUANTITY_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_QUANTITY_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_QUANTITY_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_QUANTITY_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_QUANTITY_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_QUANTITY_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_reason,
            { COINBASEDERIVATIVES_ORDERSAPI_REASON_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_REASON_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_REASON_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_REASON_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_REASON_MASK,
              NULL,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_reason_string_64,
            { COINBASEDERIVATIVES_ORDERSAPI_REASON_STRING_64_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_REASON_STRING_64_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_REASON_STRING_64_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_REASON_STRING_64_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_REASON_STRING_64_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_REASON_STRING_64_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_receive_time,
            { COINBASEDERIVATIVES_ORDERSAPI_RECEIVE_TIME_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_RECEIVE_TIME_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_RECEIVE_TIME_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_RECEIVE_TIME_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_RECEIVE_TIME_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_RECEIVE_TIME_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_ref_sequence_number,
            { COINBASEDERIVATIVES_ORDERSAPI_REF_SEQUENCE_NUMBER_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_REF_SEQUENCE_NUMBER_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_REF_SEQUENCE_NUMBER_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_REF_SEQUENCE_NUMBER_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_REF_SEQUENCE_NUMBER_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_REF_SEQUENCE_NUMBER_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_reject_reason,
            { COINBASEDERIVATIVES_ORDERSAPI_REJECT_REASON_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_REJECT_REASON_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_REJECT_REASON_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_REJECT_REASON_DISPLAY,
              VALS(coinbasederivatives_ordersapi_reject_reason_vals),
              COINBASEDERIVATIVES_ORDERSAPI_REJECT_REASON_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_REJECT_REASON_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_request_time,
            { COINBASEDERIVATIVES_ORDERSAPI_REQUEST_TIME_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_REQUEST_TIME_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_REQUEST_TIME_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_REQUEST_TIME_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_REQUEST_TIME_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_REQUEST_TIME_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_request_trading_lock,
            { COINBASEDERIVATIVES_ORDERSAPI_REQUEST_TRADING_LOCK_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_REQUEST_TRADING_LOCK_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_REQUEST_TRADING_LOCK_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_REQUEST_TRADING_LOCK_DISPLAY,
              VALS(coinbasederivatives_ordersapi_request_trading_lock_vals),
              COINBASEDERIVATIVES_ORDERSAPI_REQUEST_TRADING_LOCK_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_REQUEST_TRADING_LOCK_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_resend_reject_reason,
            { COINBASEDERIVATIVES_ORDERSAPI_RESEND_REJECT_REASON_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_RESEND_REJECT_REASON_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_RESEND_REJECT_REASON_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_RESEND_REJECT_REASON_DISPLAY,
              VALS(coinbasederivatives_ordersapi_resend_reject_reason_vals),
              COINBASEDERIVATIVES_ORDERSAPI_RESEND_REJECT_REASON_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_RESEND_REJECT_REASON_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_resent_event_count,
            { COINBASEDERIVATIVES_ORDERSAPI_RESENT_EVENT_COUNT_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_RESENT_EVENT_COUNT_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_RESENT_EVENT_COUNT_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_RESENT_EVENT_COUNT_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_RESENT_EVENT_COUNT_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_RESENT_EVENT_COUNT_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_reserved,
            { COINBASEDERIVATIVES_ORDERSAPI_RESERVED_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_RESERVED_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_RESERVED_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_RESERVED_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_RESERVED_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_RESERVED_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_reserved_byte,
            { COINBASEDERIVATIVES_ORDERSAPI_RESERVED_BYTE_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_RESERVED_BYTE_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_RESERVED_BYTE_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_RESERVED_BYTE_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_RESERVED_BYTE_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_RESERVED_BYTE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_reset_seq_num,
            { COINBASEDERIVATIVES_ORDERSAPI_RESET_SEQ_NUM_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_RESET_SEQ_NUM_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_RESET_SEQ_NUM_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_RESET_SEQ_NUM_DISPLAY,
              VALS(coinbasederivatives_ordersapi_reset_seq_num_vals),
              COINBASEDERIVATIVES_ORDERSAPI_RESET_SEQ_NUM_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_RESET_SEQ_NUM_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_schema_id,
            { COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_DISPLAY,
              VALS(coinbasederivatives_ordersapi_schema_id_vals),
              COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_SCHEMA_ID_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_security_type,
            { COINBASEDERIVATIVES_ORDERSAPI_SECURITY_TYPE_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_SECURITY_TYPE_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_SECURITY_TYPE_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_SECURITY_TYPE_DISPLAY,
              VALS(coinbasederivatives_ordersapi_security_type_vals),
              COINBASEDERIVATIVES_ORDERSAPI_SECURITY_TYPE_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_SECURITY_TYPE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_send_time_epoch_nanos,
            { COINBASEDERIVATIVES_ORDERSAPI_SEND_TIME_EPOCH_NANOS_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_SEND_TIME_EPOCH_NANOS_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_SEND_TIME_EPOCH_NANOS_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_SEND_TIME_EPOCH_NANOS_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_SEND_TIME_EPOCH_NANOS_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_SEND_TIME_EPOCH_NANOS_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_sequence_number,
            { COINBASEDERIVATIVES_ORDERSAPI_SEQUENCE_NUMBER_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_SEQUENCE_NUMBER_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_SEQUENCE_NUMBER_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_SEQUENCE_NUMBER_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_SEQUENCE_NUMBER_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_SEQUENCE_NUMBER_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_server_time,
            { COINBASEDERIVATIVES_ORDERSAPI_SERVER_TIME_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_SERVER_TIME_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_SERVER_TIME_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_SERVER_TIME_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_SERVER_TIME_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_SERVER_TIME_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_side,
            { COINBASEDERIVATIVES_ORDERSAPI_SIDE_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_SIDE_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_SIDE_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_SIDE_DISPLAY,
              VALS(coinbasederivatives_ordersapi_side_vals),
              COINBASEDERIVATIVES_ORDERSAPI_SIDE_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_SIDE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_symbol,
            { COINBASEDERIVATIVES_ORDERSAPI_SYMBOL_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_SYMBOL_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_SYMBOL_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_SYMBOL_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_SYMBOL_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_SYMBOL_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_template_id,
            { COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_DISPLAY,
              VALS(coinbasederivatives_ordersapi_template_id_vals),
              COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_TEMPLATE_ID_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_time_in_force,
            { COINBASEDERIVATIVES_ORDERSAPI_TIME_IN_FORCE_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_TIME_IN_FORCE_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_TIME_IN_FORCE_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_TIME_IN_FORCE_DISPLAY,
              CF_FUNC(coinbasederivatives_ordersapi_format_time_in_force),
              COINBASEDERIVATIVES_ORDERSAPI_TIME_IN_FORCE_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_TIME_IN_FORCE_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_timestamp,
            { COINBASEDERIVATIVES_ORDERSAPI_TIMESTAMP_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_TIMESTAMP_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_TIMESTAMP_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_TIMESTAMP_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_TIMESTAMP_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_TIMESTAMP_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_to_sequence_number,
            { COINBASEDERIVATIVES_ORDERSAPI_TO_SEQUENCE_NUMBER_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_TO_SEQUENCE_NUMBER_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_TO_SEQUENCE_NUMBER_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_TO_SEQUENCE_NUMBER_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_TO_SEQUENCE_NUMBER_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_TO_SEQUENCE_NUMBER_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_total_filled,
            { COINBASEDERIVATIVES_ORDERSAPI_TOTAL_FILLED_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_TOTAL_FILLED_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_TOTAL_FILLED_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_TOTAL_FILLED_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_TOTAL_FILLED_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_TOTAL_FILLED_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_trader,
            { COINBASEDERIVATIVES_ORDERSAPI_TRADER_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_TRADER_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_TRADER_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_TRADER_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_TRADER_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_TRADER_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_trading_instrument_status,
            { COINBASEDERIVATIVES_ORDERSAPI_TRADING_INSTRUMENT_STATUS_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_TRADING_INSTRUMENT_STATUS_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_TRADING_INSTRUMENT_STATUS_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_TRADING_INSTRUMENT_STATUS_DISPLAY,
              VALS(coinbasederivatives_ordersapi_trading_instrument_status_vals),
              COINBASEDERIVATIVES_ORDERSAPI_TRADING_INSTRUMENT_STATUS_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_TRADING_INSTRUMENT_STATUS_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_trading_lock_applied,
            { COINBASEDERIVATIVES_ORDERSAPI_TRADING_LOCK_APPLIED_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_TRADING_LOCK_APPLIED_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_TRADING_LOCK_APPLIED_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_TRADING_LOCK_APPLIED_DISPLAY,
              VALS(coinbasederivatives_ordersapi_trading_lock_applied_vals),
              COINBASEDERIVATIVES_ORDERSAPI_TRADING_LOCK_APPLIED_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_TRADING_LOCK_APPLIED_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_username,
            { COINBASEDERIVATIVES_ORDERSAPI_USERNAME_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_USERNAME_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_USERNAME_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_USERNAME_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_USERNAME_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_USERNAME_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_version,
            { COINBASEDERIVATIVES_ORDERSAPI_VERSION_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_VERSION_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_VERSION_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_VERSION_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_VERSION_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_VERSION_DESCRIPTION,
              HFILL } },

        /* Bit Fields */
        { &hf_coinbasederivatives_ordersapi_is_resend,
            { COINBASEDERIVATIVES_ORDERSAPI_IS_RESEND_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_IS_RESEND_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_IS_RESEND_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_IS_RESEND_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_IS_RESEND_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_IS_RESEND_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_post_only,
            { COINBASEDERIVATIVES_ORDERSAPI_POST_ONLY_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_POST_ONLY_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_POST_ONLY_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_POST_ONLY_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_POST_ONLY_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_POST_ONLY_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_reserved_7,
            { COINBASEDERIVATIVES_ORDERSAPI_RESERVED_7_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_RESERVED_7_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_RESERVED_7_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_RESERVED_7_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_RESERVED_7_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_RESERVED_7_DESCRIPTION,
              HFILL } },

        /* Bitfields */
        { &hf_coinbasederivatives_ordersapi_flags,
            { COINBASEDERIVATIVES_ORDERSAPI_FLAGS_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_FLAGS_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_FLAGS_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_FLAGS_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_FLAGS_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_FLAGS_DESCRIPTION,
              HFILL } },
        { &hf_coinbasederivatives_ordersapi_flags_v15,
            { COINBASEDERIVATIVES_ORDERSAPI_FLAGS_V15_NAME,
              COINBASEDERIVATIVES_ORDERSAPI_FLAGS_V15_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_FLAGS_V15_TYPE,
              COINBASEDERIVATIVES_ORDERSAPI_FLAGS_V15_DISPLAY,
              NULL,
              COINBASEDERIVATIVES_ORDERSAPI_FLAGS_V15_MASK,
              COINBASEDERIVATIVES_ORDERSAPI_FLAGS_V15_DESCRIPTION,
              HFILL } },
    };

    static int *ett[] = {
        &ett_coinbasederivatives_ordersapi,
        &ett_coinbasederivatives_ordersapi_header,
        &ett_coinbasederivatives_ordersapi_message,
        &ett_coinbasederivatives_ordersapi_flags,
        &ett_coinbasederivatives_ordersapi_flags_v15,
        &ett_coinbasederivatives_ordersapi_message_header,
        &ett_coinbasederivatives_ordersapi_data,
        &ett_coinbasederivatives_ordersapi_message_header_v15,
    };

    static ei_register_info ei[] = {
        { &ei_coinbasederivatives_ordersapi_length,
            { COINBASEDERIVATIVES_ORDERSAPI_LENGTH_EXPERT_FILTER,
              COINBASEDERIVATIVES_ORDERSAPI_LENGTH_EXPERT_GROUP,
              COINBASEDERIVATIVES_ORDERSAPI_LENGTH_EXPERT_SEVERITY,
              COINBASEDERIVATIVES_ORDERSAPI_LENGTH_EXPERT_SUMMARY,
              EXPFILL } },
    };

    proto_coinbasederivatives_ordersapi = proto_register_protocol(COINBASEDERIVATIVES_ORDERSAPI_PROTOCOL_NAME, COINBASEDERIVATIVES_ORDERSAPI_PROTOCOL_SHORT, COINBASEDERIVATIVES_ORDERSAPI_PROTOCOL_FILTER);

    proto_register_field_array(proto_coinbasederivatives_ordersapi, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_module_t *expert_coinbasederivatives_ordersapi = expert_register_protocol(proto_coinbasederivatives_ordersapi);
    expert_register_field_array(expert_coinbasederivatives_ordersapi, ei, array_length(ei));

    module_t *preferences = prefs_register_protocol(proto_coinbasederivatives_ordersapi, NULL);

    prefs_register_enum_preference(
        preferences,
        COINBASEDERIVATIVES_ORDERSAPI_VERSION_PREFERENCE_NAME,
        COINBASEDERIVATIVES_ORDERSAPI_VERSION_PREFERENCE_TITLE,
        COINBASEDERIVATIVES_ORDERSAPI_VERSION_PREFERENCE_DESCRIPTION,
        &coinbasederivatives_ordersapi_pref_version,
        coinbasederivatives_ordersapi_version_vals,
        false);

    prefs_register_bool_preference(
        preferences,
        COINBASEDERIVATIVES_ORDERSAPI_SHOW_HEADERS_PREFERENCE_NAME,
        COINBASEDERIVATIVES_ORDERSAPI_SHOW_HEADERS_PREFERENCE_TITLE,
        COINBASEDERIVATIVES_ORDERSAPI_SHOW_HEADERS_PREFERENCE_DESCRIPTION,
        &coinbasederivatives_ordersapi_show_headers);

    prefs_register_bool_preference(
        preferences,
        COINBASEDERIVATIVES_ORDERSAPI_SHOW_SCHEMA_MESSAGES_PREFERENCE_NAME,
        COINBASEDERIVATIVES_ORDERSAPI_SHOW_SCHEMA_MESSAGES_PREFERENCE_TITLE,
        COINBASEDERIVATIVES_ORDERSAPI_SHOW_SCHEMA_MESSAGES_PREFERENCE_DESCRIPTION,
        &coinbasederivatives_ordersapi_show_schema_messages);

    prefs_register_bool_preference(
        preferences,
        COINBASEDERIVATIVES_ORDERSAPI_SHOW_APPLICATION_MESSAGES_PREFERENCE_NAME,
        COINBASEDERIVATIVES_ORDERSAPI_SHOW_APPLICATION_MESSAGES_PREFERENCE_TITLE,
        COINBASEDERIVATIVES_ORDERSAPI_SHOW_APPLICATION_MESSAGES_PREFERENCE_DESCRIPTION,
        &coinbasederivatives_ordersapi_show_application_messages);

    prefs_register_bool_preference(
        preferences,
        COINBASEDERIVATIVES_ORDERSAPI_SHOW_STRUCTS_PREFERENCE_NAME,
        COINBASEDERIVATIVES_ORDERSAPI_SHOW_STRUCTS_PREFERENCE_TITLE,
        COINBASEDERIVATIVES_ORDERSAPI_SHOW_STRUCTS_PREFERENCE_DESCRIPTION,
        &coinbasederivatives_ordersapi_show_structs);

    prefs_register_uint_preference(
        preferences,
        COINBASEDERIVATIVES_ORDERSAPI_DECIMAL_PREFERENCE_NAME,
        COINBASEDERIVATIVES_ORDERSAPI_DECIMAL_PREFERENCE_TITLE,
        COINBASEDERIVATIVES_ORDERSAPI_DECIMAL_PREFERENCE_DESCRIPTION,
        10,
        &coinbasederivatives_ordersapi_pref_decimal_places);

    coinbasederivatives_ordersapi_handle = register_dissector(COINBASEDERIVATIVES_ORDERSAPI_PROTOCOL_FILTER, dissect_coinbasederivatives_ordersapi, proto_coinbasederivatives_ordersapi);
}

void
proto_reg_handoff_coinbasederivatives_ordersapi(void)
{
    heur_dissector_add("tcp", dissect_coinbasederivatives_ordersapi_heur, "CoinbaseDerivatives OrdersApi over TCP",
        "coinbasederivatives_ordersapi_tcp", proto_coinbasederivatives_ordersapi, HEURISTIC_ENABLE);

    dissector_add_for_decode_as("tcp.port", coinbasederivatives_ordersapi_handle);
}
