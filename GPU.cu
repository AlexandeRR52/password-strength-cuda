#include <stdio.h>
#include <cuda_runtime.h>
#include <string.h>
#include <time.h>
#include "sha1.cuh"
#include "GPU.h"
#define PASSWORD_MAX_LENGTH 64
#define MAX_PASSWORDS 500000
__device__ __constant__ uint8_t d_targetHash[20];
__device__ __constant__ char    d_salt[64];

__device__ volatile int stopFlag = 0;

__device__ int gpu_strcspn(const char* str1, char ch)
{
    int i = 0;
    while(str1[i] != '\0' && str1[i] != ch)
        i++;
    return i;
    
}
__global__ void GPUCore(int cnt, char (*data)[PASSWORD_MAX_LENGTH])
{
    unsigned long long idx = blockIdx.x * blockDim.x + threadIdx.x;
    if(idx >= cnt ||stopFlag != 0)
        return;

    int f = 0;
    char* password = data[idx];
    uint8_t hash[20];
    gpu_sha1_hash((uint8_t*)password, (uint8_t*)d_salt, hash);

    f = 1;
    #pragma unroll
    for(int k = 0; k < 20; k++)
    {
        if(hash[k] != d_targetHash[k])
        {
            f = 0;
            break;
        }
    }
    if(f == 0)
        return;
    
    if(atomicExch((int*)&stopFlag, 1) == 0)
    {
        printf("Collision found: %s\n", password);
        printf("Used salt: %s\n", d_salt);
        printf("Hash: ");
        for (int i = 0; i < 20; i++)
            printf("%02x", hash[i]);
        printf("\n");
        return;
    }
}
extern "C" void DictBruteGPU(char salt[]) {
    char localSalt[512];
    strcpy(localSalt, salt);
    int localcnt = 0;
    clock_t start;
    double gpu_time_used;

    
    start = clock();
    
    FILE* passwords = fopen("passwds1.txt", "r");
    FILE* mainPass = fopen("mainPass.txt", "r");

    uint8_t mainHash[20];
    char hexHash[41];
    
    fgets(hexHash, sizeof(hexHash), mainPass);
    
    for (int i = 0; i < 20; i++)
        sscanf(&hexHash[i * 2], "%2hhx", &mainHash[i]);
    printf("Target hash & salt: ");
    
    for (int i = 0; i < 20; i++)
    printf("%02x", mainHash[i]);
    
    printf(" %s\n", localSalt);
    
    printf("\nStarting dictionary brute-force on GPU...\n");
    char (*data)[PASSWORD_MAX_LENGTH];
    int zero = 0;
    cudaMemcpyToSymbol(stopFlag, &zero, sizeof(int), 0, cudaMemcpyHostToDevice);
    int cnt = 0;
    uint8_t* d_mainHash;
    cudaMalloc(&d_mainHash, 20 * sizeof(uint8_t));
    cudaMemcpy(d_mainHash, mainHash, 20 * sizeof(uint8_t), cudaMemcpyHostToDevice);

    char* d_salt;
    cudaMalloc(&d_salt, 512 * sizeof(char));
    cudaMemcpy(d_salt, localSalt, 512 * sizeof(char), cudaMemcpyHostToDevice);
    while(1)
    {
        localcnt = 0;
        data = (char (*)[PASSWORD_MAX_LENGTH])malloc(MAX_PASSWORDS * PASSWORD_MAX_LENGTH * sizeof(char));
        while(localcnt < MAX_PASSWORDS && fgets((char*)data[localcnt], PASSWORD_MAX_LENGTH, passwords) != NULL)
        {
            data[localcnt][strcspn((char*)data[localcnt], "\n")] = '\0';
            cnt++;
            localcnt++;
        }
        char (*d_data)[PASSWORD_MAX_LENGTH];
        cudaMalloc(&d_data, localcnt * PASSWORD_MAX_LENGTH * sizeof(char));
        cudaMemcpyAsync(d_data, data, localcnt * PASSWORD_MAX_LENGTH * sizeof(char), cudaMemcpyHostToDevice);

        int threadsPerBlock = 256;
        int blocksPerGrid = (localcnt + threadsPerBlock - 1) / threadsPerBlock;
        
        GPUCore<<<blocksPerGrid, threadsPerBlock>>>(localcnt, d_data);
        cudaDeviceSynchronize();
        cudaFree(d_data);
        cudaFree(d_mainHash);
        
        free(data);
        int h_flag = 0;
        cudaMemcpyFromSymbol(&h_flag, stopFlag, sizeof(int));
        if (h_flag != 0 || localcnt < MAX_PASSWORDS)
            break;
    }
    
    fclose(passwords);
    fclose(mainPass);
    gpu_time_used = ((double)(clock() - start)) / CLOCKS_PER_SEC;
    printf("GPU Time used: %.3f s.\n", gpu_time_used);
}
