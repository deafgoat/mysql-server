#ifdef __cplusplus
#define BSON_BEGIN_DECLS extern "C" {
#define BSON_END_DECLS }
#else
#define BSON_BEGIN_DECLS
#define BSON_END_DECLS
#endif

typedef struct {
   uint32_t domain;
   uint32_t code;
   char message[504];
} bson_error_t;