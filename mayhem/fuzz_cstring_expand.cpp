#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>

typedef struct _cstring_t {
    wchar_t *value;
    size_t size;
    size_t alloc;
    void (*expand)(struct _cstring_t *self, wchar_t x);
    void (*expand_arr)(struct _cstring_t *self, wchar_t *x);
    void (*strip)(struct _cstring_t *self, int pos, int len);
    void (*reset)(struct _cstring_t *self);
    void (*dlete)(struct _cstring_t *self);
} cstring_t;

extern "C" cstring_t* cstring_init();
extern "C" void cstring_delete(cstring_t *self);
extern "C" void cstring_expand(cstring_t *self, wchar_t x);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    wchar_t x = provider.ConsumeIntegral<wchar_t>();
    
    cstring_t* cstring = cstring_init();

    cstring_expand(cstring, x);

    cstring_delete(cstring);

    return 0;
}