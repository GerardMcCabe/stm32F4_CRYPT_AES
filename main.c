#include "stm32f4xx.h"
#include "stm32f4xx_rcc.h"
#include "stm32f4xx_gpio.h"
#include "stm32f4xx_usart.h"
#include "stm32f4xx_cryp.h"
#include "stdio.h"

#define AES_TEXT_SIZE    64

#define ECB              1
#define CBC              2
#define CTR              3

#define AESBUSY_TIMEOUT    ((uint32_t) 0x00010000)


uint8_t AES128key[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
                      0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c}; /* key size 128 bytes */

uint8_t AES192key[24] = {0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52,
                      0xc8,0x10,0xf3,0x2b,0x80,0x90,0x79,0xe5,
                      0x62,0xf8,0xea,0xd2,0x52,0x2c,0x6b,0x7b}; /* key size 192 bytes */

uint8_t AES256key[32] = {0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
                      0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
                      0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
                      0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4}; /* key size 256 bytes */

uint8_t IV_1[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                     0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f}; /* initialization vector */


uint8_t Plaintext[AES_TEXT_SIZE] =
                        {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
                         0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
                         0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,
                         0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
                         0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,
                         0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
                         0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,
                         0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10}; /* plaintext */


uint8_t Ciphertext[AES_TEXT_SIZE] =
                        {0x76,0x49,0xab,0xac,0x81,0x19,0xb2,0x46,
                         0xce,0xe9,0x8e,0x9b,0x12,0xe9,0x19,0x7d,
                         0x50,0x86,0xcb,0x9b,0x50,0x72,0x19,0xee,
                         0x95,0xdb,0x11,0x3a,0x91,0x76,0x78,0xb2,
                         0x73,0xbe,0xd6,0xb8,0xe3,0xc1,0x74,0x3b,
                         0x71,0x16,0xe6,0x9e,0x22,0x22,0x95,0x16,
                         0x3f,0xf1,0xca,0xa1,0x68,0x1f,0xac,0x09,
                         0x12,0x0e,0xca,0x30,0x75,0x86,0xe1,0xa7}; /* ciphertext */

uint8_t Encryptedtext[AES_TEXT_SIZE]; /* Encrypted text */
uint8_t Decryptedtext[AES_TEXT_SIZE]; /* Decrypted text */


void USART_Config(void);
void Display_PlainData(uint32_t datalength);
void Display_EncryptedData(uint8_t mode,uint16_t keysize,uint32_t datalength);
void Display_DecryptedData(uint8_t mode,uint16_t keysize,uint32_t datalength);
char PressToContinue(void);

void delay(int i)
{
	while(i--){
	}
}

#if 0
void AES_Mode(void)
{
   /* Enable CRYP clock */
  RCC_AHB2PeriphClockCmd(RCC_AHB2Periph_CRYP, ENABLE);


    /* Display Plain Data*/
    Display_PlainData(AES_TEXT_SIZE);


    /* Encrypt the plaintext message*/
    CRYP_AES_ECB(MODE_ENCRYPT,AES128key,128,Plaintext,AES_TEXT_SIZE,Encryptedtext);

    /* Display encrypted Data*/
    Display_EncryptedData(ECB,128,AES_TEXT_SIZE);


    /* Encrypt the plaintext message*/
    CRYP_AES_ECB(MODE_ENCRYPT,AES192key,192,Plaintext,AES_TEXT_SIZE,Encryptedtext);

    /* Display encrypted Data*/
    Display_EncryptedData(ECB,192,AES_TEXT_SIZE);


    /* Encrypt the plaintext message*/
    CRYP_AES_ECB(MODE_ENCRYPT,AES256key,256,Plaintext,AES_TEXT_SIZE,Encryptedtext);

    /* Display encrypted Data*/
    Display_EncryptedData(ECB, 256,AES_TEXT_SIZE);


    /* Decrypt the plaintext message  */
    CRYP_AES_ECB(MODE_DECRYPT,AES128key,128,Ciphertext,AES_TEXT_SIZE,Decryptedtext);

    /* Display decrypted data*/
    Display_DecryptedData(ECB,128,AES_TEXT_SIZE);

    /* Decrypt the plaintext message  */
    CRYP_AES_ECB(MODE_DECRYPT,AES192key, 192,Ciphertext, AES_TEXT_SIZE,Decryptedtext);

    /* Display decrypted data*/
    Display_DecryptedData(ECB, 192,AES_TEXT_SIZE);

    /* Decrypt the plaintext message  */
    CRYP_AES_ECB(MODE_DECRYPT,AES256key, 256,Ciphertext, AES_TEXT_SIZE,Decryptedtext);

    /* Display decrypted data*/
    Display_DecryptedData(ECB,256,AES_TEXT_SIZE);



    /* Encrypt the plaintext message*/
    CRYP_AES_CBC(MODE_ENCRYPT,IV_1,AES128key,128,Plaintext,AES_TEXT_SIZE,Encryptedtext);

    /* Display encrypted Data*/
    Display_EncryptedData(CBC,128,AES_TEXT_SIZE);

    /* Encrypt the plaintext message*/
    CRYP_AES_CBC(MODE_ENCRYPT,IV_1,AES192key,192,Plaintext,AES_TEXT_SIZE,Encryptedtext);

    /* Display encrypted Data*/
    Display_EncryptedData(CBC,192,AES_TEXT_SIZE);

    /* Encrypt the plaintext message*/
    CRYP_AES_CBC(MODE_ENCRYPT,IV_1,AES256key,256,Plaintext,AES_TEXT_SIZE,Encryptedtext);

    /* Display encrypted Data*/
    Display_EncryptedData(CBC, 256,AES_TEXT_SIZE);


    /* Deinitializes the CRYP peripheral */
    CRYP_DeInit();

    /* Decrypt the plaintext message  */
    CRYP_AES_CBC(MODE_DECRYPT,IV_1,AES128key,128,Ciphertext,AES_TEXT_SIZE,Decryptedtext);

    /* Display decrypted data*/
    Display_DecryptedData(CBC,128,AES_TEXT_SIZE);

    /* Deinitializes the CRYP peripheral */
    CRYP_DeInit();

    /* Decrypt the plaintext message  */
    CRYP_AES_CBC(MODE_DECRYPT,IV_1,AES192key, 192,Ciphertext, AES_TEXT_SIZE,Decryptedtext);

    /* Display decrypted data*/
    Display_DecryptedData(CBC, 192,AES_TEXT_SIZE);

    /* Deinitializes the CRYP peripheral */
    CRYP_DeInit();

    /* Decrypt the plaintext message  */
    CRYP_AES_CBC(MODE_DECRYPT,IV_1,AES256key, 256,Ciphertext, AES_TEXT_SIZE,Decryptedtext);

    /* Display decrypted data*/
    Display_DecryptedData(CBC,256,AES_TEXT_SIZE);



    /* Encrypt the plaintext message*/
    CRYP_AES_CTR(MODE_ENCRYPT,IV_1,AES128key,128,Plaintext,AES_TEXT_SIZE,Encryptedtext);

    /* Display encrypted Data*/
    Display_EncryptedData(CTR,128, AES_TEXT_SIZE);
/****************************************/
/*                           AES 192   **/
/****************************************/
    /* Encrypt the plaintext message*/
    CRYP_AES_CTR(MODE_ENCRYPT,IV_1,AES192key,192,Plaintext,AES_TEXT_SIZE,Encryptedtext);

    /* Display encrypted Data*/
    Display_EncryptedData(CTR,192, AES_TEXT_SIZE);
/****************************************/
/*                           AES 256   **/
/****************************************/
    /* Encrypt the plaintext message*/
    CRYP_AES_CTR(MODE_ENCRYPT,IV_1,AES256key,256,Plaintext,AES_TEXT_SIZE,Encryptedtext);

    /* Display encrypted Data*/
    Display_EncryptedData(CTR, 256, AES_TEXT_SIZE);

/*=====================================================
    Decryption in CTR mode
======================================================*/
   PressToContinue();
/****************************************/
/*                           AES 128   **/
/****************************************/
    /* Decrypt the plaintext message  */
    CRYP_AES_CTR(MODE_DECRYPT,IV_1,AES128key,128,Ciphertext,AES_TEXT_SIZE,Decryptedtext);

    /* Display decrypted data*/
    Display_DecryptedData(CTR, 128, AES_TEXT_SIZE);
/****************************************/
/*                           AES 192   **/
/****************************************/
    /* Decrypt the plaintext message  */
    CRYP_AES_CTR(MODE_DECRYPT,IV_1,AES192key,192,Ciphertext,AES_TEXT_SIZE,Decryptedtext);

    /* Display decrypted data*/
    Display_DecryptedData(CTR, 192, AES_TEXT_SIZE);
/****************************************/
/*                           AES 256   **/
/****************************************/
    /* Decrypt the plaintext message  */
    CRYP_AES_CTR(MODE_DECRYPT,IV_1,AES256key, 256,Ciphertext, AES_TEXT_SIZE,Decryptedtext);

    /* Display decrypted data*/
    Display_DecryptedData(CTR, 256, AES_TEXT_SIZE);

/******************************************************************************/


}
#endif

#if 0
/**
  * @brief  Display Plain Data
  * @param  datalength: length of the data to display
  * @retval None
  */
void Display_PlainData(uint32_t datalength)
{
  uint32_t BufferCounter =0;
  uint32_t count = 0;

  printf("\n\r =============================================================\n\r");
  printf(" ================= Crypt Using HW Crypto  ====================\n\r");
  printf(" ============================================================\n\r");
  printf(" ---------------------------------------\n\r");
  printf(" Plain Data :\n\r");
  printf(" ---------------------------------------\n\r");

  for(BufferCounter = 0; BufferCounter < datalength; BufferCounter++)
  {
    printf("[0x%02X]", Plaintext[BufferCounter]);
    count++;

    if(count == 16)
    {
      count = 0;
      printf("  Block %d \n\r", BufferCounter/16);
    }
  }
}
#endif

#if 0
/**
  * @brief  Display Encrypted Data
  * @param  mode: chaining mode
  * @param  keysize: AES key size used
  * @param  datalength: length of the data to display
  * @retval None
  */


void Display_EncryptedData(uint8_t mode, uint16_t keysize, uint32_t datalength)
{
  uint32_t BufferCounter = 0;
  uint32_t count = 0;

  printf("\n\r =======================================\n\r");
  printf(" Encrypted Data with AES %d  Mode  ",keysize );

  if(mode == ECB)
  {
    printf("ECB\n\r");
  }
  else if(mode == CBC)
  {
    printf("CBC\n\r");
  }
  else /* if(mode == CTR)*/
  {
    printf("CTR\n\r");
  }

  printf(" ---------------------------------------\n\r");

  for(BufferCounter = 0; BufferCounter < datalength; BufferCounter++)
  {
    printf("[0x%02X]", Encryptedtext[BufferCounter]);

    count++;
    if(count == 16)
    {
      count = 0;
      printf(" Block %d \n\r", BufferCounter/16);
    }
  }
}
#endif

#if 0
/**
  * @brief  Display Decrypted Data
  * @param  mode: chaining mode
  * @param  keysize: AES key size used
  * @param  datalength: length of the data to display
  * @retval None
  */
void Display_DecryptedData(uint8_t mode, uint16_t keysize, uint32_t datalength)
{
  uint32_t BufferCounter = 0;
  uint32_t count = 0;

  printf("\n\r =======================================\n\r");
  printf(" Decrypted Data with AES %d  Mode  ",keysize );

  if(mode == ECB)
  {
    printf("ECB\n\r");
  }
  else if(mode == CBC)
  {
    printf("CBC\n\r");
  }
  else /* if(mode == CTR)*/
  {
    printf("CTR\n\r");
  }

  printf(" ---------------------------------------\n\r");

  for(BufferCounter = 0; BufferCounter < datalength; BufferCounter++)
  {
    printf("[0x%02X]", Decryptedtext[BufferCounter]);
    count++;

    if(count == 16)
    {
      count = 0;
      printf(" Block %d \n\r", BufferCounter/16);
    }
  }
}
#endif

#if 0
void USART_Config(void)
{

  GPIO_InitTypeDef GPIO_InitStructure;
  USART_InitTypeDef USART_InitStructure;

  /* Enable GPIO clock */
  RCC_AHB1PeriphClockCmd(RCC_AHB1Periph_GPIOC, ENABLE);

  /* Enable UART clock */
  RCC_APB1PeriphClockCmd(RCC_APB1Periph_USART3, ENABLE);

  /* Connect PXx to USARTx_Tx*/
  GPIO_PinAFConfig(GPIOC, GPIO_PinSource10, GPIO_AF_USART3);

  /* Connect PXx to USARTx_Rx*/
  GPIO_PinAFConfig(GPIOC, GPIO_PinSource11, GPIO_AF_USART3);

  /* Configure USART Tx as alternate function  */
  GPIO_InitStructure.GPIO_OType = GPIO_OType_PP;
  GPIO_InitStructure.GPIO_PuPd = GPIO_PuPd_UP;
  GPIO_InitStructure.GPIO_Mode = GPIO_Mode_AF;

  GPIO_InitStructure.GPIO_Pin = GPIO_Pin_10;
  GPIO_InitStructure.GPIO_Speed = GPIO_Speed_50MHz;
  GPIO_Init(GPIOC, &GPIO_InitStructure);

  /* Configure USART Rx as alternate function  */
  GPIO_InitStructure.GPIO_Mode = GPIO_Mode_AF;
  GPIO_InitStructure.GPIO_Pin = GPIO_Pin_11;
  GPIO_Init(GPIOC, &GPIO_InitStructure);

  USART_InitStructure.USART_BaudRate = 115200;
  USART_InitStructure.USART_WordLength = USART_WordLength_8b;
  USART_InitStructure.USART_StopBits = USART_StopBits_1;
  USART_InitStructure.USART_Parity = USART_Parity_No;
  USART_InitStructure.USART_HardwareFlowControl = USART_HardwareFlowControl_None;
  USART_InitStructure.USART_Mode = USART_Mode_Rx | USART_Mode_Tx;

  /* USART configuration */
  USART_Init(USART3, &USART_InitStructure);

  /* Enable USART */
  USART_Cmd(USART3, ENABLE);
}
#endif

void configUSART()
{
	USART_InitTypeDef USART_InitStruct;
	GPIO_InitTypeDef GPIO_InitStruct;

	RCC_APB1PeriphClockCmd(RCC_APB1Periph_UART5, ENABLE);
	RCC_AHB1PeriphClockCmd(RCC_AHB1Periph_GPIOC , ENABLE);
	RCC_AHB1PeriphClockCmd(RCC_AHB1Periph_GPIOD , ENABLE);

	/* Config TX GPIO pin C12 */
	GPIO_InitStruct.GPIO_Pin = GPIO_Pin_12;
	GPIO_InitStruct.GPIO_Mode = GPIO_Mode_AF;
	GPIO_InitStruct.GPIO_OType = GPIO_OType_PP;
	GPIO_InitStruct.GPIO_PuPd = GPIO_PuPd_NOPULL;
	GPIO_InitStruct.GPIO_Speed = GPIO_Speed_100MHz;
	GPIO_Init(GPIOC, &GPIO_InitStruct);
	GPIO_PinAFConfig(GPIOC, GPIO_PinSource12, GPIO_AF_UART5);

	/* Config RX GPIO pin D2 as input floating */
	GPIO_InitStruct.GPIO_Pin = GPIO_Pin_2;
	GPIO_InitStruct.GPIO_Mode = GPIO_Mode_AF;
	GPIO_InitStruct.GPIO_OType = GPIO_OType_PP;
	GPIO_InitStruct.GPIO_PuPd = GPIO_PuPd_NOPULL;
	GPIO_InitStruct.GPIO_Speed = GPIO_Speed_100MHz;
	GPIO_Init(GPIOD, &GPIO_InitStruct);
	GPIO_PinAFConfig(GPIOD, GPIO_PinSource2, GPIO_AF_UART5);

	USART_InitStruct.USART_BaudRate = 115200;
	USART_InitStruct.USART_HardwareFlowControl = USART_HardwareFlowControl_None;
	USART_InitStruct.USART_Mode = USART_Mode_Tx | USART_Mode_Rx;
	USART_InitStruct.USART_Parity = USART_Parity_No;
	USART_InitStruct.USART_StopBits = USART_StopBits_1;
	USART_InitStruct.USART_WordLength = USART_WordLength_8b;

	USART_Init(UART5, &USART_InitStruct);


	USART_Cmd(UART5, ENABLE);
}

void USART_puts(USART_TypeDef* USART5,  char *s)
{
	int i = 0;
	for (i = 0; i < 30; i++)
	{
		// wait until data register is empty
		while(USART_GetFlagStatus(UART5, USART_FLAG_TC) == RESET);
		USART_SendData(USART5, s[i]);
		/* terminate the loop using break statement, FF is terminator */
		if( s[i] == 0x00)
		  {
			  break;
		  }
	}
}


int main(void)
{

	SystemInit();
	configUSART();

	/* Enable CRYP clock */
	RCC_AHB2PeriphClockCmd(RCC_AHB2Periph_CRYP, ENABLE);

	/* Display Plain Data*/
	USART_puts(UART5, "Plain text:\n\r");
	USART_puts(UART5, Plaintext);

	/* Encrypt the plaintext message*/
	CRYP_AES_ECB(MODE_ENCRYPT,AES128key,2128,Plaintext,AES_TEXT_SIZE,Encryptedtext);

	/* Display encrypted Data*/
	USART_puts(UART5, "Encrypted data:\n\r");
	USART_puts(UART5, Encryptedtext);

	USART_puts(UART5, "End...\n\r");

	while(1) {}
}
