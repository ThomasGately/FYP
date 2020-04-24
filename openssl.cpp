

#include <openssl/err.h>
#include <openssl/ssl.h>
	#include <openssl/crypto.h>

	static CRYPTO_ONCE once = CRYPTO_ONCE_STATIC_INIT;
	static CRYPTO_RWLOCK *lock;

void startup()
{
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
	ERR_load_crypto_strings();
}


	static void myinit(void)
	{
			lock = CRYPTO_THREAD_lock_new();
	}

	static int mylock(void)
	{
			if (!CRYPTO_THREAD_run_once(&once, startup) || lock == NULL)
					return 0;
			return CRYPTO_THREAD_write_lock(lock);
	}

	static int myunlock(void)
	{
			return CRYPTO_THREAD_unlock(lock);
	}

	int serialized(void)
	{
			int ret = 0;

			if (mylock()) {
					/* Your code here, do not return without releasing the lock! */
					ret = 0  ;
			}
			myunlock();
			return ret;
	}

	int main(int count, char *strings[]) {


return 0;
}