//
//  vector.c
//  live_transcoder
//
//  Created by Guy.Jacubovski on 27/03/2019.
//  Copyright © 2019 Kaltura. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>

#include "vector.h"

void vector_init(vector_t *v)
{
    v->capacity = VECTOR_INIT_CAPACITY;
    v->total = 0;
    v->items = malloc(sizeof(void *) * v->capacity);
}

int vector_total(vector_t *v)
{
    return v->total;
}

static void vector_resize(vector_t *v, int capacity)
{
#ifdef DEBUG_ON
    printf("vector_resize: %d to %d\n", v->capacity, capacity);
#endif
    
    void **items = realloc(v->items, sizeof(void *) * capacity);
    if (items) {
        v->items = items;
        v->capacity = capacity;
    }
}

void vector_add(vector_t *v, void *item)
{
    if (v->capacity == v->total)
        vector_resize(v, v->capacity * 2);
    v->items[v->total++] = item;
}

void vector_set(vector_t *v, int index, void *item)
{
    if (index >= 0 && index < v->total)
        v->items[index] = item;
}

void *vector_get(vector_t *v, int index)
{
    if (index >= 0 && index < v->total)
        return v->items[index];
    return NULL;
}

void vector_delete(vector_t *v, int index)
{
    if (index < 0 || index >= v->total)
        return;
    
    v->items[index] = NULL;
    
    for (int i = index; i < v->total - 1; i++) {
        v->items[i] = v->items[i + 1];
        v->items[i + 1] = NULL;
    }
    
    v->total--;
    
    if (v->total > 0 && v->total == v->capacity / 4)
        vector_resize(v, v->capacity / 2);
}

void vector_free(vector_t *v)
{
    free(v->items);
}
