#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>

#if HAVE_RISTRETTO
#include "ristretto.h"
#else
/* Stub definitions when RistrettoDB is not available */
typedef struct RistrettoTable RistrettoTable;

typedef enum {
    RISTRETTO_COL_INTEGER,
    RISTRETTO_COL_REAL,
    RISTRETTO_COL_TEXT,
    RISTRETTO_COL_NULLABLE
} RistrettoColumnType;

typedef struct {
    union {
        int64_t integer;
        double real;
        struct {
            const char *data;
            size_t length;
        } text;
    } value;
    RistrettoColumnType type;
    bool is_null;
} RistrettoValue;

typedef struct {
    const char *name;
    RistrettoColumnType type;
    size_t size;
    size_t offset;
} RistrettoColumnDesc;

#define RISTRETTO_VERSION "stub-1.0.0"
#define RISTRETTO_VERSION_NUMBER 100
#endif

/* Internal structure for stub RistrettoTable */
struct RistrettoTable {
    char name[64];
    uint64_t row_count;
    bool is_open;
};

/* Internal structure for stub RistrettoDB */
struct RistrettoDB {
    char filename[256];
    bool is_open;
};

/* Stub implementations for RistrettoDB functions */

/* Version functions */
const char* ristretto_version(void) {
    return RISTRETTO_VERSION;
}

int ristretto_version_number(void) {
    return RISTRETTO_VERSION_NUMBER;
}

/* Table V2 API stub implementations */
RistrettoTable* ristretto_table_create(const char *name, const char *schema_sql) {
    (void)schema_sql;  /* Unused in stub */
    
    RistrettoTable* table = malloc(sizeof(struct RistrettoTable));
    if (table) {
        strncpy(table->name, name, sizeof(table->name) - 1);
        table->name[sizeof(table->name) - 1] = '\0';
        table->row_count = 0;
        table->is_open = true;
        printf("RistrettoDB stub: Created table '%s'\n", name);
    }
    return table;
}

RistrettoTable* ristretto_table_open(const char *name) {
    RistrettoTable* table = malloc(sizeof(struct RistrettoTable));
    if (table) {
        strncpy(table->name, name, sizeof(table->name) - 1);
        table->name[sizeof(table->name) - 1] = '\0';
        table->row_count = 0;
        table->is_open = true;
        printf("RistrettoDB stub: Opened table '%s'\n", name);
    }
    return table;
}

void ristretto_table_close(RistrettoTable *table) {
    if (table) {
        printf("RistrettoDB stub: Closed table\n");
        free(table);
    }
}

bool ristretto_table_append_row(RistrettoTable *table, const RistrettoValue *values) {
    (void)values;
    
    if (!table) return false;
    
    table->row_count++;
    
    if (table->row_count % 100 == 0) {
        printf("RistrettoDB stub: Appended %" PRIu64 " rows to table '%s'\n", 
               table->row_count, table->name);
    }
    
    return true;  /* Always succeed in stub */
}

bool ristretto_table_flush(RistrettoTable *table) {
    (void)table;
    printf("RistrettoDB stub: Flushed table to disk\n");
    return true;
}

/* Value creation functions */
RistrettoValue ristretto_value_integer(int64_t val) {
    RistrettoValue value;
    value.type = RISTRETTO_COL_INTEGER;
    value.value.integer = val;
    value.is_null = false;
    return value;
}

RistrettoValue ristretto_value_real(double val) {
    RistrettoValue value;
    value.type = RISTRETTO_COL_REAL;
    value.value.real = val;
    value.is_null = false;
    return value;
}

RistrettoValue ristretto_value_text(const char *str) {
    RistrettoValue value;
    value.type = RISTRETTO_COL_TEXT;
    
    if (str) {
        value.value.text.length = strlen(str);
        value.value.text.data = strdup(str);  /* Allocate copy */
        value.is_null = false;
    } else {
        value.value.text.length = 0;
        value.value.text.data = NULL;
        value.is_null = true;
    }
    
    return value;
}

RistrettoValue ristretto_value_null(void) {
    RistrettoValue value;
    value.type = RISTRETTO_COL_NULLABLE;
    value.is_null = true;
    memset(&value.value, 0, sizeof(value.value));
    return value;
}

void ristretto_value_destroy(RistrettoValue *value) {
    if (value && value->type == RISTRETTO_COL_TEXT && value->value.text.data) {
        free(value->value.text.data);
        value->value.text.data = NULL;
        value->value.text.length = 0;
    }
}

/* Utility functions */
uint64_t ristretto_get_time_ms(void) {
    return 0;  /* Stub implementation */
}

bool ristretto_create_data_directory(void) {
    return true;  /* Stub always succeeds */
}

/* Additional stub functions not used but may be referenced */
bool ristretto_table_select(RistrettoTable *table, const char *where_clause,
                           void (*callback)(void *ctx, const RistrettoValue *row), void *ctx) {
    (void)table;
    (void)where_clause;
    (void)callback;
    (void)ctx;
    return true;
}

bool ristretto_table_remap(RistrettoTable *table) {
    (void)table;
    return true;
}

bool ristretto_table_ensure_space(RistrettoTable *table, size_t needed_bytes) {
    (void)table;
    (void)needed_bytes;
    return true;
}

bool ristretto_table_parse_schema(const char *schema_sql, RistrettoColumnDesc *columns,
                                 uint32_t *column_count, uint32_t *row_size) {
    (void)schema_sql;
    (void)columns;
    (void)column_count;
    (void)row_size;
    return true;
}

const RistrettoColumnDesc* ristretto_table_get_column(RistrettoTable *table, const char *name) {
    (void)table;
    (void)name;
    return NULL;
}

size_t ristretto_table_get_row_count(RistrettoTable *table) {
    (void)table;
    return 0;
}

bool ristretto_table_pack_row(RistrettoTable *table, const RistrettoValue *values, uint8_t *row_buffer) {
    (void)table;
    (void)values;
    (void)row_buffer;
    return true;
}

bool ristretto_table_unpack_row(RistrettoTable *table, const uint8_t *row_buffer, RistrettoValue *values) {
    (void)table;
    (void)row_buffer;
    (void)values;
    return true;
}
