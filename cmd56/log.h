#ifdef _DEBUG
#define LOG(...) printf(__VA_ARGS__)
#define LOG_BUFFER(buffer, size) for(int i = 0; i < size; i++) { LOG("%02X ", ((unsigned char*)buffer)[i]); }; LOG("\n");
#else
#define LOG(...) /**/
#define LOG_BUFFER(buffer, size) /**/
#endif