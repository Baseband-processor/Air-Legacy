#include <stdint.h>
#include <string.h>

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include "ppport.h"

#define SHA1_DIGEST_LEN 20

typedef struct{
    uint32_t total[2];
    uint32_t state[5];
    uint8_t buffer[64];
}sha1_context;

typedef struct {
    sha1_context ctx;
    uint8_t k_opad[64];
}sha1_hmac_context;



MODULE = Air::Lorcon2   PACKAGE = Air::Lorcon2::Extra
PROTOTYPES: DISABLE

void
sha1_process(ctx, data)
    sha1_context *ctx
    uint8_t data

    
void 
sha1_update( ctx, input, length )
  sha1_context *ctx
  uint8_t *input
  uint32_t length
PPCODE:
    uint32_t left, fill;

    if( ! length ){
      return -1;
    }
    left = ctx->total[0] & 0x3F;
    fill = 64 - left;

    ctx->total[0] += length;
    ctx->total[0] &= 0xFFFFFFFF;

    if( ctx->total[0] < length )
        ctx->total[1]++;

    if( left && length >= fill ){
        //memcpy( (void *) (ctx->buffer + left), (const void *) input, fill );
        Copy(input, (ctx->buffer + left), fill, 1);
        sha1_process( ctx, ctx->buffer );
        length -= fill;
        input  += fill;
        left = 0;
    }

    while( length >= 64 ){
        sha1_process( ctx, input );
        length -= 64;
        input  += 64;
    }

    if( length ){
        //memcpy( (void *) (ctx->buffer + left), (const void *) input, length );
        Copy(input,  (ctx->buffer + left), length, 1);
    }
    
void 
sha1_finish( ctx, digest )
  sha1_context *ctx
  uint8_t digest
CODE:
    uint8_t sha1_padding[64] = {
       0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    uint32_t last, padn;
    uint32_t high, low;
    uint8_t msglen[8];

    high = ( ctx->total[0] >> 29 )
         | ( ctx->total[1] <<  3 );
    low  = ( ctx->total[0] <<  3 );

    PUT_UINT32( high, msglen, 0 );
    PUT_UINT32( low,  msglen, 4 );

    last = ctx->total[0] & 0x3F;
    padn = ( last < 56 ) ? ( 56 - last ) : ( 120 - last );

    sha1_update( ctx, sha1_padding, padn );
    sha1_update( ctx, msglen, 8 );

    PUT_UINT32( ctx->state[0], digest,  0 );
    PUT_UINT32( ctx->state[1], digest,  4 );
    PUT_UINT32( ctx->state[2], digest,  8 );
    PUT_UINT32( ctx->state[3], digest, 12 );
    PUT_UINT32( ctx->state[4], digest, 16 );
    
void 
sha1_starts( ctx )
  sha1_context *ctx
CODE:
    ctx->total[0] = 0;
    ctx->total[1] = 0;

    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
    
void 
sha1_hmac_starts( hctx, key, keylength )
    sha1_hmac_context *hctx
    uint8_t *key
    uint32_t keylength
CODE:
    uint32_t i;
    uint8_t k_ipad[64];    
    //memset( k_ipad, 0x36, 64 );
    Zero(k_ipad, 0x36, 64);
    //memset( hctx->k_opad, 0x5C, 64 );
    Zero(hctx->k_opad, 0x5C, 64);

    for( i = 0; i < keylength; i++ )
    {
        if( i >= 64 ) break;

        k_ipad[i] ^= key[i];
        hctx->k_opad[i] ^= key[i];
    }

    sha1_starts( &hctx->ctx );
    sha1_update( &hctx->ctx, k_ipad, 64 );


void 
sha1_hmac_update( hctx, buf, buflength )
    sha1_hmac_context *hctx
    uint8_t *buf
    uint32_t buflength
CODE:
    sha1_update( &hctx->ctx, buf, buflength );


void 
sha1_hmac_finish( hctx, digest )
    sha1_hmac_context *hctx
    uint8_t digest
CODE:
    uint8_t tmpbuf;
    sha1_finish( &hctx->ctx, tmpbuf );
    sha1_starts( &hctx->ctx );
    sha1_update( &hctx->ctx, hctx->k_opad, 64 );
    sha1_update( &hctx->ctx, tmpbuf, SHA1_DIGEST_LEN );
    sha1_finish( &hctx->ctx, digest );


void 
sha1_hmac( key, keylength, buf, buflength, digest )
    uint8_t *key
    uint32_t keylength
    uint8_t *buf
    uint32_t buflength
    uint8_t digest
CODE:
    sha1_hmac_context hctx;

    sha1_hmac_starts( &hctx, key, keylength );
    sha1_hmac_update( &hctx, buf, buflength );
    sha1_hmac_finish( &hctx, digest );

