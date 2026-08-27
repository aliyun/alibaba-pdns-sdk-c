/*
  Copyright (c) 2009-2017 Dave Gamble and pdns_cJSON contributors

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
*/

#ifndef pdns_cJSON__h
#define pdns_cJSON__h

#ifdef __cplusplus
extern "C"
{
#endif

#if !defined(__WINDOWS__) && (defined(WIN32) || defined(WIN64) || defined(_MSC_VER) || defined(_WIN32))
#define __WINDOWS__
#endif

#ifdef __WINDOWS__

/* When compiling for windows, we specify a specific calling convention to avoid issues where we are being called from a project with a different default calling convention.  For windows you have 3 define options:

PDNS_CJSON_HIDE_SYMBOLS - Define this in the case where you don't want to ever dllexport symbols
PDNS_CJSON_EXPORT_SYMBOLS - Define this on library build when you want to dllexport symbols (default)
PDNS_CJSON_IMPORT_SYMBOLS - Define this if you want to dllimport symbol

For *nix builds that support visibility attribute, you can define similar behavior by

setting default visibility to hidden by adding
-fvisibility=hidden (for gcc)
or
-xldscope=hidden (for sun cc)
to CFLAGS

then using the PDNS_CJSON_API_VISIBILITY flag to "export" the same symbols the way PDNS_CJSON_EXPORT_SYMBOLS does

*/

#define PDNS_CJSON_CDECL __cdecl
#define PDNS_CJSON_STDCALL __stdcall

/* export symbols by default, this is necessary for copy pasting the C and header file */
#if !defined(PDNS_CJSON_HIDE_SYMBOLS) && !defined(PDNS_CJSON_IMPORT_SYMBOLS) && !defined(PDNS_CJSON_EXPORT_SYMBOLS)
#define PDNS_CJSON_EXPORT_SYMBOLS
#endif

#if defined(PDNS_CJSON_HIDE_SYMBOLS)
#define PDNS_CJSON_PUBLIC(type)   type PDNS_CJSON_STDCALL
#elif defined(PDNS_CJSON_EXPORT_SYMBOLS)
#define PDNS_CJSON_PUBLIC(type)   __declspec(dllexport) type PDNS_CJSON_STDCALL
#elif defined(PDNS_CJSON_IMPORT_SYMBOLS)
#define PDNS_CJSON_PUBLIC(type)   __declspec(dllimport) type PDNS_CJSON_STDCALL
#endif
#else /* !__WINDOWS__ */
#define PDNS_CJSON_CDECL
#define PDNS_CJSON_STDCALL

#if (defined(__GNUC__) || defined(__SUNPRO_CC) || defined (__SUNPRO_C)) && defined(PDNS_CJSON_API_VISIBILITY)
#define PDNS_CJSON_PUBLIC(type)   __attribute__((visibility("default"))) type
#else
#define PDNS_CJSON_PUBLIC(type) type
#endif
#endif

/* project version */
#define PDNS_CJSON_VERSION_MAJOR 1
#define PDNS_CJSON_VERSION_MINOR 7
#define PDNS_CJSON_VERSION_PATCH 18

#include <stddef.h>

/* pdns_cJSON Types: */
#define pdns_cJSON_Invalid (0)
#define pdns_cJSON_False  (1 << 0)
#define pdns_cJSON_True   (1 << 1)
#define pdns_cJSON_NULL   (1 << 2)
#define pdns_cJSON_Number (1 << 3)
#define pdns_cJSON_String (1 << 4)
#define pdns_cJSON_Array  (1 << 5)
#define pdns_cJSON_Object (1 << 6)
#define pdns_cJSON_Raw    (1 << 7) /* raw json */

#define pdns_cJSON_IsReference 256
#define pdns_cJSON_StringIsConst 512

/* The pdns_cJSON structure: */
typedef struct pdns_cJSON
{
    /* next/prev allow you to walk array/object chains. Alternatively, use GetArraySize/GetArrayItem/GetObjectItem */
    struct pdns_cJSON *next;
    struct pdns_cJSON *prev;
    /* An array or object item will have a child pointer pointing to a chain of the items in the array/object. */
    struct pdns_cJSON *child;

    /* The type of the item, as above. */
    int type;

    /* The item's string, if type==pdns_cJSON_String  and type == pdns_cJSON_Raw */
    char *valuestring;
    /* writing to valueint is DEPRECATED, use pdns_cJSON_SetNumberValue instead */
    int valueint;
    /* The item's number, if type==pdns_cJSON_Number */
    double valuedouble;

    /* The item's name string, if this item is the child of, or is in the list of subitems of an object. */
    char *string;
} pdns_cJSON;

typedef struct pdns_cJSON_Hooks
{
      /* malloc/free are CDECL on Windows regardless of the default calling convention of the compiler, so ensure the hooks allow passing those functions directly. */
      void *(PDNS_CJSON_CDECL *malloc_fn)(size_t sz);
      void (PDNS_CJSON_CDECL *free_fn)(void *ptr);
} pdns_cJSON_Hooks;

typedef int pdns_cJSON_bool;

/* Limits how deeply nested arrays/objects can be before pdns_cJSON rejects to parse them.
 * This is to prevent stack overflows. */
#ifndef PDNS_CJSON_NESTING_LIMIT
#define PDNS_CJSON_NESTING_LIMIT 1000
#endif

/* returns the version of pdns_cJSON as a string */
PDNS_CJSON_PUBLIC(const char*) pdns_cJSON_Version(void);

/* Supply malloc, realloc and free functions to pdns_cJSON */
PDNS_CJSON_PUBLIC(void) pdns_cJSON_InitHooks(pdns_cJSON_Hooks* hooks);

/* Memory Management: the caller is always responsible to free the results from all variants of pdns_cJSON_Parse (with pdns_cJSON_Delete) and pdns_cJSON_Print (with stdlib free, pdns_cJSON_Hooks.free_fn, or pdns_cJSON_free as appropriate). The exception is pdns_cJSON_PrintPreallocated, where the caller has full responsibility of the buffer. */
/* Supply a block of JSON, and this returns a pdns_cJSON object you can interrogate. */
PDNS_CJSON_PUBLIC(pdns_cJSON *) pdns_cJSON_Parse(const char *value);
PDNS_CJSON_PUBLIC(pdns_cJSON *) pdns_cJSON_ParseWithLength(const char *value, size_t buffer_length);
/* ParseWithOpts allows you to require (and check) that the JSON is null terminated, and to retrieve the pointer to the final byte parsed. */
/* If you supply a ptr in return_parse_end and parsing fails, then return_parse_end will contain a pointer to the error so will match pdns_cJSON_GetErrorPtr(). */
PDNS_CJSON_PUBLIC(pdns_cJSON *) pdns_cJSON_ParseWithOpts(const char *value, const char **return_parse_end, pdns_cJSON_bool require_null_terminated);
PDNS_CJSON_PUBLIC(pdns_cJSON *) pdns_cJSON_ParseWithLengthOpts(const char *value, size_t buffer_length, const char **return_parse_end, pdns_cJSON_bool require_null_terminated);

/* Render a pdns_cJSON entity to text for transfer/storage. */
PDNS_CJSON_PUBLIC(char *) pdns_cJSON_Print(const pdns_cJSON *item);
/* Render a pdns_cJSON entity to text for transfer/storage without any formatting. */
PDNS_CJSON_PUBLIC(char *) pdns_cJSON_PrintUnformatted(const pdns_cJSON *item);
/* Render a pdns_cJSON entity to text using a buffered strategy. prebuffer is a guess at the final size. guessing well reduces reallocation. fmt=0 gives unformatted, =1 gives formatted */
PDNS_CJSON_PUBLIC(char *) pdns_cJSON_PrintBuffered(const pdns_cJSON *item, int prebuffer, pdns_cJSON_bool fmt);
/* Render a pdns_cJSON entity to text using a buffer already allocated in memory with given length. Returns 1 on success and 0 on failure. */
/* NOTE: pdns_cJSON is not always 100% accurate in estimating how much memory it will use, so to be safe allocate 5 bytes more than you actually need */
PDNS_CJSON_PUBLIC(pdns_cJSON_bool) pdns_cJSON_PrintPreallocated(pdns_cJSON *item, char *buffer, const int length, const pdns_cJSON_bool format);
/* Delete a pdns_cJSON entity and all subentities. */
PDNS_CJSON_PUBLIC(void) pdns_cJSON_Delete(pdns_cJSON *item);

/* Returns the number of items in an array (or object). */
PDNS_CJSON_PUBLIC(int) pdns_cJSON_GetArraySize(const pdns_cJSON *array);
/* Retrieve item number "index" from array "array". Returns NULL if unsuccessful. */
PDNS_CJSON_PUBLIC(pdns_cJSON *) pdns_cJSON_GetArrayItem(const pdns_cJSON *array, int index);
/* Get item "string" from object. Case insensitive. */
PDNS_CJSON_PUBLIC(pdns_cJSON *) pdns_cJSON_GetObjectItem(const pdns_cJSON * const object, const char * const string);
PDNS_CJSON_PUBLIC(pdns_cJSON *) pdns_cJSON_GetObjectItemCaseSensitive(const pdns_cJSON * const object, const char * const string);
PDNS_CJSON_PUBLIC(pdns_cJSON_bool) pdns_cJSON_HasObjectItem(const pdns_cJSON *object, const char *string);
/* For analysing failed parses. This returns a pointer to the parse error. You'll probably need to look a few chars back to make sense of it. Defined when pdns_cJSON_Parse() returns 0. 0 when pdns_cJSON_Parse() succeeds. */
PDNS_CJSON_PUBLIC(const char *) pdns_cJSON_GetErrorPtr(void);

/* Check item type and return its value */
PDNS_CJSON_PUBLIC(char *) pdns_cJSON_GetStringValue(const pdns_cJSON * const item);
PDNS_CJSON_PUBLIC(double) pdns_cJSON_GetNumberValue(const pdns_cJSON * const item);

/* These functions check the type of an item */
PDNS_CJSON_PUBLIC(pdns_cJSON_bool) pdns_cJSON_IsInvalid(const pdns_cJSON * const item);
PDNS_CJSON_PUBLIC(pdns_cJSON_bool) pdns_cJSON_IsFalse(const pdns_cJSON * const item);
PDNS_CJSON_PUBLIC(pdns_cJSON_bool) pdns_cJSON_IsTrue(const pdns_cJSON * const item);
PDNS_CJSON_PUBLIC(pdns_cJSON_bool) pdns_cJSON_IsBool(const pdns_cJSON * const item);
PDNS_CJSON_PUBLIC(pdns_cJSON_bool) pdns_cJSON_IsNull(const pdns_cJSON * const item);
PDNS_CJSON_PUBLIC(pdns_cJSON_bool) pdns_cJSON_IsNumber(const pdns_cJSON * const item);
PDNS_CJSON_PUBLIC(pdns_cJSON_bool) pdns_cJSON_IsString(const pdns_cJSON * const item);
PDNS_CJSON_PUBLIC(pdns_cJSON_bool) pdns_cJSON_IsArray(const pdns_cJSON * const item);
PDNS_CJSON_PUBLIC(pdns_cJSON_bool) pdns_cJSON_IsObject(const pdns_cJSON * const item);
PDNS_CJSON_PUBLIC(pdns_cJSON_bool) pdns_cJSON_IsRaw(const pdns_cJSON * const item);

/* These calls create a pdns_cJSON item of the appropriate type. */
PDNS_CJSON_PUBLIC(pdns_cJSON *) pdns_cJSON_CreateNull(void);
PDNS_CJSON_PUBLIC(pdns_cJSON *) pdns_cJSON_CreateTrue(void);
PDNS_CJSON_PUBLIC(pdns_cJSON *) pdns_cJSON_CreateFalse(void);
PDNS_CJSON_PUBLIC(pdns_cJSON *) pdns_cJSON_CreateBool(pdns_cJSON_bool boolean);
PDNS_CJSON_PUBLIC(pdns_cJSON *) pdns_cJSON_CreateNumber(double num);
PDNS_CJSON_PUBLIC(pdns_cJSON *) pdns_cJSON_CreateString(const char *string);
/* raw json */
PDNS_CJSON_PUBLIC(pdns_cJSON *) pdns_cJSON_CreateRaw(const char *raw);
PDNS_CJSON_PUBLIC(pdns_cJSON *) pdns_cJSON_CreateArray(void);
PDNS_CJSON_PUBLIC(pdns_cJSON *) pdns_cJSON_CreateObject(void);

/* Create a string where valuestring references a string so
 * it will not be freed by pdns_cJSON_Delete */
PDNS_CJSON_PUBLIC(pdns_cJSON *) pdns_cJSON_CreateStringReference(const char *string);
/* Create an object/array that only references it's elements so
 * they will not be freed by pdns_cJSON_Delete */
PDNS_CJSON_PUBLIC(pdns_cJSON *) pdns_cJSON_CreateObjectReference(const pdns_cJSON *child);
PDNS_CJSON_PUBLIC(pdns_cJSON *) pdns_cJSON_CreateArrayReference(const pdns_cJSON *child);

/* These utilities create an Array of count items.
 * The parameter count cannot be greater than the number of elements in the number array, otherwise array access will be out of bounds.*/
PDNS_CJSON_PUBLIC(pdns_cJSON *) pdns_cJSON_CreateIntArray(const int *numbers, int count);
PDNS_CJSON_PUBLIC(pdns_cJSON *) pdns_cJSON_CreateFloatArray(const float *numbers, int count);
PDNS_CJSON_PUBLIC(pdns_cJSON *) pdns_cJSON_CreateDoubleArray(const double *numbers, int count);
PDNS_CJSON_PUBLIC(pdns_cJSON *) pdns_cJSON_CreateStringArray(const char *const *strings, int count);

/* Append item to the specified array/object. */
PDNS_CJSON_PUBLIC(pdns_cJSON_bool) pdns_cJSON_AddItemToArray(pdns_cJSON *array, pdns_cJSON *item);
PDNS_CJSON_PUBLIC(pdns_cJSON_bool) pdns_cJSON_AddItemToObject(pdns_cJSON *object, const char *string, pdns_cJSON *item);
/* Use this when string is definitely const (i.e. a literal, or as good as), and will definitely survive the pdns_cJSON object.
 * WARNING: When this function was used, make sure to always check that (item->type & pdns_cJSON_StringIsConst) is zero before
 * writing to `item->string` */
PDNS_CJSON_PUBLIC(pdns_cJSON_bool) pdns_cJSON_AddItemToObjectCS(pdns_cJSON *object, const char *string, pdns_cJSON *item);
/* Append reference to item to the specified array/object. Use this when you want to add an existing pdns_cJSON to a new pdns_cJSON, but don't want to corrupt your existing pdns_cJSON. */
PDNS_CJSON_PUBLIC(pdns_cJSON_bool) pdns_cJSON_AddItemReferenceToArray(pdns_cJSON *array, pdns_cJSON *item);
PDNS_CJSON_PUBLIC(pdns_cJSON_bool) pdns_cJSON_AddItemReferenceToObject(pdns_cJSON *object, const char *string, pdns_cJSON *item);

/* Remove/Detach items from Arrays/Objects. */
PDNS_CJSON_PUBLIC(pdns_cJSON *) pdns_cJSON_DetachItemViaPointer(pdns_cJSON *parent, pdns_cJSON * const item);
PDNS_CJSON_PUBLIC(pdns_cJSON *) pdns_cJSON_DetachItemFromArray(pdns_cJSON *array, int which);
PDNS_CJSON_PUBLIC(void) pdns_cJSON_DeleteItemFromArray(pdns_cJSON *array, int which);
PDNS_CJSON_PUBLIC(pdns_cJSON *) pdns_cJSON_DetachItemFromObject(pdns_cJSON *object, const char *string);
PDNS_CJSON_PUBLIC(pdns_cJSON *) pdns_cJSON_DetachItemFromObjectCaseSensitive(pdns_cJSON *object, const char *string);
PDNS_CJSON_PUBLIC(void) pdns_cJSON_DeleteItemFromObject(pdns_cJSON *object, const char *string);
PDNS_CJSON_PUBLIC(void) pdns_cJSON_DeleteItemFromObjectCaseSensitive(pdns_cJSON *object, const char *string);

/* Update array items. */
PDNS_CJSON_PUBLIC(pdns_cJSON_bool) pdns_cJSON_InsertItemInArray(pdns_cJSON *array, int which, pdns_cJSON *newitem); /* Shifts pre-existing items to the right. */
PDNS_CJSON_PUBLIC(pdns_cJSON_bool) pdns_cJSON_ReplaceItemViaPointer(pdns_cJSON * const parent, pdns_cJSON * const item, pdns_cJSON * replacement);
PDNS_CJSON_PUBLIC(pdns_cJSON_bool) pdns_cJSON_ReplaceItemInArray(pdns_cJSON *array, int which, pdns_cJSON *newitem);
PDNS_CJSON_PUBLIC(pdns_cJSON_bool) pdns_cJSON_ReplaceItemInObject(pdns_cJSON *object,const char *string,pdns_cJSON *newitem);
PDNS_CJSON_PUBLIC(pdns_cJSON_bool) pdns_cJSON_ReplaceItemInObjectCaseSensitive(pdns_cJSON *object,const char *string,pdns_cJSON *newitem);

/* Duplicate a pdns_cJSON item */
PDNS_CJSON_PUBLIC(pdns_cJSON *) pdns_cJSON_Duplicate(const pdns_cJSON *item, pdns_cJSON_bool recurse);
/* Duplicate will create a new, identical pdns_cJSON item to the one you pass, in new memory that will
 * need to be released. With recurse!=0, it will duplicate any children connected to the item.
 * The item->next and ->prev pointers are always zero on return from Duplicate. */
/* Recursively compare two pdns_cJSON items for equality. If either a or b is NULL or invalid, they will be considered unequal.
 * case_sensitive determines if object keys are treated case sensitive (1) or case insensitive (0) */
PDNS_CJSON_PUBLIC(pdns_cJSON_bool) pdns_cJSON_Compare(const pdns_cJSON * const a, const pdns_cJSON * const b, const pdns_cJSON_bool case_sensitive);

/* Minify a strings, remove blank characters(such as ' ', '\t', '\r', '\n') from strings.
 * The input pointer json cannot point to a read-only address area, such as a string constant, 
 * but should point to a readable and writable address area. */
PDNS_CJSON_PUBLIC(void) pdns_cJSON_Minify(char *json);

/* Helper functions for creating and adding items to an object at the same time.
 * They return the added item or NULL on failure. */
PDNS_CJSON_PUBLIC(pdns_cJSON*) pdns_cJSON_AddNullToObject(pdns_cJSON * const object, const char * const name);
PDNS_CJSON_PUBLIC(pdns_cJSON*) pdns_cJSON_AddTrueToObject(pdns_cJSON * const object, const char * const name);
PDNS_CJSON_PUBLIC(pdns_cJSON*) pdns_cJSON_AddFalseToObject(pdns_cJSON * const object, const char * const name);
PDNS_CJSON_PUBLIC(pdns_cJSON*) pdns_cJSON_AddBoolToObject(pdns_cJSON * const object, const char * const name, const pdns_cJSON_bool boolean);
PDNS_CJSON_PUBLIC(pdns_cJSON*) pdns_cJSON_AddNumberToObject(pdns_cJSON * const object, const char * const name, const double number);
PDNS_CJSON_PUBLIC(pdns_cJSON*) pdns_cJSON_AddStringToObject(pdns_cJSON * const object, const char * const name, const char * const string);
PDNS_CJSON_PUBLIC(pdns_cJSON*) pdns_cJSON_AddRawToObject(pdns_cJSON * const object, const char * const name, const char * const raw);
PDNS_CJSON_PUBLIC(pdns_cJSON*) pdns_cJSON_AddObjectToObject(pdns_cJSON * const object, const char * const name);
PDNS_CJSON_PUBLIC(pdns_cJSON*) pdns_cJSON_AddArrayToObject(pdns_cJSON * const object, const char * const name);

/* When assigning an integer value, it needs to be propagated to valuedouble too. */
#define pdns_cJSON_SetIntValue(object, number) ((object) ? (object)->valueint = (object)->valuedouble = (number) : (number))
/* helper for the pdns_cJSON_SetNumberValue macro */
PDNS_CJSON_PUBLIC(double) pdns_cJSON_SetNumberHelper(pdns_cJSON *object, double number);
#define pdns_cJSON_SetNumberValue(object, number) ((object != NULL) ? pdns_cJSON_SetNumberHelper(object, (double)number) : (number))
/* Change the valuestring of a pdns_cJSON_String object, only takes effect when type of object is pdns_cJSON_String */
PDNS_CJSON_PUBLIC(char*) pdns_cJSON_SetValuestring(pdns_cJSON *object, const char *valuestring);

/* If the object is not a boolean type this does nothing and returns pdns_cJSON_Invalid else it returns the new type*/
#define pdns_cJSON_SetBoolValue(object, boolValue) ( \
    (object != NULL && ((object)->type & (pdns_cJSON_False|pdns_cJSON_True))) ? \
    (object)->type=((object)->type &(~(pdns_cJSON_False|pdns_cJSON_True)))|((boolValue)?pdns_cJSON_True:pdns_cJSON_False) : \
    pdns_cJSON_Invalid\
)

/* Macro for iterating over an array or object */
#define pdns_cJSON_ArrayForEach(element, array) for(element = (array != NULL) ? (array)->child : NULL; element != NULL; element = element->next)

/* malloc/free objects using the malloc/free functions that have been set with pdns_cJSON_InitHooks */
PDNS_CJSON_PUBLIC(void *) pdns_cJSON_malloc(size_t size);
PDNS_CJSON_PUBLIC(void) pdns_cJSON_free(void *object);

#ifdef __cplusplus
}
#endif

#endif
