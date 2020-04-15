#define RandomUntilNonExistant(X,map) do{sgx_read_rand((unsigned char*)(&X), sizeof(X));}while(X != 0 && map##TypeGet(&map, X) == 0)
