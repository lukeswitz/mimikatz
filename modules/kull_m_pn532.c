/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kull_m_pn532.h"

void kull_m_pn532_init(PKULL_M_PN532_COMM_CALLBACK communicator, LPVOID suppdata, BOOL descr, PKULL_M_PN532_COMM comm)
{
	comm->communicator = communicator;
	comm->suppdata = suppdata;
	comm->descr = descr;
}

BOOL kull_m_pn532_sendrecv(PKULL_M_PN532_COMM comm, const BYTE pn532_cmd, const BYTE *pbData, const UINT16 cbData, BYTE *pbResult, UINT16 *cbResult)
{
	BOOL status = FALSE;
	BYTE buffer[PN532_MAX_LEN];
	UINT16 cbIn = cbData + 2, cbOut = *cbResult + 2;

	if(comm->communicator)
	{
	if((cbIn <= sizeof(buffer)) && (cbOut <= sizeof(buffer)))
	{
		if(!(pn532_cmd & 1))
		{
			buffer[0] = PN532_Host_PN532;
			buffer[1] = pn532_cmd;
			if(cbData)
				RtlCopyMemory(buffer + 2, pbData, cbData);
			if(comm->descr)
			{
				kprintf(L"PN532> ");
				kull_m_string_wprintf_hex(buffer, cbIn, 1);
				kprintf(L"\n");
			}
			if(comm->communicator(buffer, cbIn, buffer, &cbOut, comm->suppdata))
			{
				if(comm->descr)
				{
					kprintf(L"PN532< ");
					kull_m_string_wprintf_hex(buffer, cbOut, 1);
					kprintf(L"\n");
				}

				if(cbOut >= 2)
				{
					*cbResult = cbOut - 2;
					if(buffer[0] == PN532_PN532_Host)
					{
						if(status = (buffer[1] == pn532_cmd + 1))
							RtlCopyMemory(pbResult, buffer + 2, *cbResult);
						else PRINT_ERROR(L"Recv CC is not valid: 0x%02x, expected 0x%02x\n", buffer[1], pn532_cmd + 1);
					}
					else PRINT_ERROR(L"Recv TFI is not valid: 0x%02x, expected 0x%02x\n", buffer[0], PN532_PN532_Host);
				}
				else PRINT_ERROR(L"cbOut = %hu (not long enough)\n", cbOut);
			}
		}
		else PRINT_ERROR(L"pn532_cmd is not even (0x%02x)\n", pn532_cmd);
	}
	else PRINT_ERROR(L"cbIn = %hu / cbOut = %hu (max is %hu)\n", cbIn, cbOut, sizeof(buffer));
	}
	else PRINT_ERROR(L"No communicator\n");
	return status;
}


BOOL kull_m_pn532_Diagnose(PKULL_M_PN532_COMM comm /*, ...*/)
{
	BOOL status = FALSE;
	return status;
}

BOOL kull_m_pn532_GetFirmware(PKULL_M_PN532_COMM comm, BYTE firmwareInfo[4])
{
	BOOL status = FALSE;
	UINT16 wRet = 4;
	if(kull_m_pn532_sendrecv(comm, PN532_CMD_GetFirmwareVersion, NULL, 0, firmwareInfo, &wRet))
		status = (wRet == 4);
	return status;
}

BOOL kull_m_pn532_GetGeneralStatus(PKULL_M_PN532_COMM comm /*, ...*/)
{
	BOOL status = FALSE;
	BYTE ret[3 + 4 + 4 + 1];
	UINT16 wRet = sizeof(ret);
	kull_m_pn532_sendrecv(comm, PN532_CMD_GetGeneralStatus, NULL, 0, ret, &wRet);
	return status;
}

BOOL kull_m_pn532_InListPassiveTarget(PKULL_M_PN532_COMM comm, const BYTE MaxTg, const BYTE BrTy, const BYTE *pbInit, UINT16 cbInit, BYTE *NbTg, PPN532_TARGET *Targets)
{
	BOOL status = FALSE;
	BYTE dataIn[2 + 12] = {MaxTg, BrTy}, dataOut[PN532_MAX_LEN - 14], i, *ptr;
	UINT16 wOut = sizeof(dataOut);

	if(BrTy == 0)
	{
		if(cbInit <= sizeof(dataIn) - 2)
		{
			if(cbInit)
				RtlCopyMemory(dataIn + 2, pbInit, cbInit);
			if(kull_m_pn532_sendrecv(comm, PN532_CMD_InListPassiveTarget, dataIn, cbInit + 2, dataOut, &wOut))
			{
				if(dataOut[0])
				{
					if(NbTg && Targets)
					{
						*NbTg = dataOut[0];
						if(*Targets = (PPN532_TARGET) LocalAlloc(LPTR, *NbTg * sizeof(PN532_TARGET) + wOut - 1)) // not efficient, but...
						{
							ptr = (PBYTE) *Targets + *NbTg * sizeof(PN532_TARGET);
							RtlCopyMemory(ptr, dataOut + 1, wOut - 1);
							for(i = 0; i < dataOut[0]; i++)
							{
								(*Targets)[i].Tg = *ptr++;
								(*Targets)[i].BrTy = BrTy;
								switch(BrTy)
								{
								case 0:
									(*Targets)[i].Target.TypeA.Tg = (*Targets)[i].Tg;
									(*Targets)[i].Target.TypeA.SENS_RES = *(PUINT16) ptr;
									ptr += sizeof((*Targets)[i].Target.TypeA.SENS_RES);
									(*Targets)[i].Target.TypeA.SEL_RES = *ptr++;
									(*Targets)[i].Target.TypeA.NFCIDLength = *ptr++;
									if((*Targets)[i].Target.TypeA.NFCIDLength)
									{
										(*Targets)[i].Target.TypeA.NFCID1 = ptr;
										ptr += (*Targets)[i].Target.TypeA.NFCIDLength;
									}
									if((*Targets)[i].Target.TypeA.SEL_RES & 0x20)
									{
										(*Targets)[i].Target.TypeA.ATSLength = *ptr++;
										if((*Targets)[i].Target.TypeA.ATSLength)
										{
											(*Targets)[i].Target.TypeA.ATS = ptr;
											ptr += (*Targets)[i].Target.TypeA.ATSLength;
										}
									}
									break;
								}
							}
							status = TRUE;
						}
					}
					else status = TRUE;
				}
			}
		}
		else PRINT_ERROR(L"cbInit is: %hu, max is %hu\n", cbInit, sizeof(dataIn) - 2);
	}
	else PRINT_ERROR(L"Only BrTy = 0 (TypeA) at this time\n");
	return status;
}

BOOL kull_m_pn532_InListPassiveTarget_TypeB(PKULL_M_PN532_COMM comm, const BYTE MaxTg, PPN532_TARGET_TYPEB *pTarget)
{
    BOOL status = FALSE;
    BYTE data[4], dataLen = 0;
    BYTE responseData[PN532_MAX_LEN];
    BYTE responseLen = sizeof(responseData);
    
    if(!comm || !pTarget)
        return FALSE;
        
    // Prepare Type B command
    data[dataLen++] = MaxTg;    // MaxTg
    data[dataLen++] = 0x01;     // BrTy = 0x01 for Type B
    
    // Send InListPassiveTarget command
    if(kull_m_pn532_CommandandTransfer(comm, PN532_COMMAND_INLISTPASSIVETARGET, data, dataLen, responseData, &responseLen))
    {
        if(responseLen >= 3)
        {
            const BYTE nbTg = responseData[0];
            if(nbTg > 0 && nbTg <= MaxTg && responseLen > 10)
            {
                RtlZeroMemory(pTarget, sizeof(PN532_TARGET_TYPEB));
                
                // Parse Type B specific fields
                pTarget->Idx = responseData[1];
                pTarget->ATQB.Length = responseLen - 2;
                
                // Copy ATQB (Answer to Request Type B)
                if(pTarget->ATQB.Length <= sizeof(pTarget->ATQB.Data))
                {
                    RtlCopyMemory(pTarget->ATQB.Data, &responseData[2], pTarget->ATQB.Length);
                    status = TRUE;
                }
            }
        }
    }
    
    return status;
}

BOOL kull_m_pn532_InListPassiveTarget_FeliCa(PKULL_M_PN532_COMM comm, const BYTE MaxTg, PPN532_TARGET_FELICA *pTarget)
{
    BOOL status = FALSE;
    BYTE data[6], dataLen = 0;
    BYTE responseData[PN532_MAX_LEN];
    BYTE responseLen = sizeof(responseData);
    
    if(!comm || !pTarget)
        return FALSE;
        
    // Prepare FeliCa command
    data[dataLen++] = MaxTg;    // MaxTg
    data[dataLen++] = 0x02;     // BrTy = 0x02 for FeliCa 212kbps
    
    // Add FeliCa system code (0xFFFF = all systems)
    data[dataLen++] = 0xFF;
    data[dataLen++] = 0xFF;
    
    // Timeout
    data[dataLen++] = 0x00;
    
    // Send InListPassiveTarget command
    if(kull_m_pn532_CommandandTransfer(comm, PN532_COMMAND_INLISTPASSIVETARGET, data, dataLen, responseData, &responseLen))
    {
        if(responseLen >= 3)
        {
            const BYTE nbTg = responseData[0];
            if(nbTg > 0 && nbTg <= MaxTg && responseLen > 20)
            {
                RtlZeroMemory(pTarget, sizeof(PN532_TARGET_FELICA));
                
                // Parse FeliCa specific fields
                pTarget->Idx = responseData[1];
                const BYTE *pData = &responseData[2];
                
                // IDm (Manufacturer ID) - 8 bytes
                RtlCopyMemory(pTarget->IDm, pData, 8);
                
                // PMm (Manufacturer Parameter) - 8 bytes
                RtlCopyMemory(pTarget->PMm, pData + 8, 8);
                
                // System code - 2 bytes (if available)
                if(responseLen >= 20)
                {
                    pTarget->SystemCode[0] = pData[16];
                    pTarget->SystemCode[1] = pData[17];
                }
                
                status = TRUE;
            }
        }
    }
    
    return status;
}

BOOL kull_m_pn532_DetectCardType(PKULL_M_PN532_COMM comm, PPN532_CARD_TYPE_INFO pCardTypeInfo)
{
    BOOL status = FALSE;
    
    if(!comm || !pCardTypeInfo)
        return FALSE;
    
    RtlZeroMemory(pCardTypeInfo, sizeof(PN532_CARD_TYPE_INFO));
    
    // Try Type A
    PN532_TARGET_TYPE_A targetA;
    if(kull_m_pn532_InListPassiveTarget(comm, 1, 0, NULL, 0, &pCardTypeInfo->NbFound, &targetA))
    {
        if(pCardTypeInfo->NbFound > 0)
        {
            pCardTypeInfo->Type = PN532_CARD_TYPE_A;
            RtlCopyMemory(&pCardTypeInfo->TypeA, &targetA, sizeof(targetA));
            status = TRUE;
        }
    }
    
    // Try Type B if Type A not found
    if(!status)
    {
        PN532_TARGET_TYPEB targetB;
        if(kull_m_pn532_InListPassiveTarget_TypeB(comm, 1, &targetB))
        {
            pCardTypeInfo->Type = PN532_CARD_TYPE_B;
            RtlCopyMemory(&pCardTypeInfo->TypeB, &targetB, sizeof(targetB));
            pCardTypeInfo->NbFound = 1;
            status = TRUE;
        }
    }
    
    // Try FeliCa if no other type found
    if(!status)
    {
        PN532_TARGET_FELICA targetF;
        if(kull_m_pn532_InListPassiveTarget_FeliCa(comm, 1, &targetF))
        {
            pCardTypeInfo->Type = PN532_CARD_TYPE_FELICA;
            RtlCopyMemory(&pCardTypeInfo->FeliCa, &targetF, sizeof(targetF));
            pCardTypeInfo->NbFound = 1;
            status = TRUE;
        }
    }
    
    return status;
}

BOOL kull_m_pn532_ReadCardData(PKULL_M_PN532_COMM comm, PPN532_CARD_TYPE_INFO pCardTypeInfo, BYTE blockNumber, BYTE *pBlockData, BYTE blockLength)
{
    BOOL status = FALSE;
    
    if(!comm || !pCardTypeInfo || !pBlockData)
        return FALSE;
    
    switch(pCardTypeInfo->Type)
    {
        case PN532_CARD_TYPE_A:
            {
                // For Type A cards, use MIFARE Classic authentication and read
                // First byte of UID is used as Key A for demonstration
                BYTE keyA[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
                
                // Authenticate with the block
                if(kull_m_pn532_Mifare_Classic_AuthBlock(comm, &pCardTypeInfo->TypeA, 0x60, blockNumber, keyA))
                {
                    // Read the data
                    BYTE cmdRead[2] = {0x30, blockNumber}; // MIFARE Read command
                    BYTE response[32];
                    BYTE responseLen = sizeof(response);
                    
                    if(kull_m_pn532_DataExchange(comm, cmdRead, sizeof(cmdRead), response, &responseLen))
                    {
                        if(responseLen >= blockLength)
                        {
                            RtlCopyMemory(pBlockData, response, blockLength);
                            status = TRUE;
                        }
                    }
                }
            }
            break;
            
        case PN532_CARD_TYPE_B:
            // Type B card reading requires specific APDU commands
            // This is a simplified implementation
            {
                // ISO 14443-4 APDU for reading
                BYTE apdu[7] = {0x00, 0xB0, 0x00, blockNumber, 0x00, blockLength, 0x00};
                BYTE response[64];
                BYTE responseLen = sizeof(response);
                
                if(kull_m_pn532_DataExchange(comm, apdu, sizeof(apdu)-1, response, &responseLen))
                {
                    if(responseLen >= blockLength + 2 && response[responseLen-2] == 0x90 && response[responseLen-1] == 0x00)
                    {
                        RtlCopyMemory(pBlockData, response, blockLength);
                        status = TRUE;
                    }
                }
            }
            break;
            
        case PN532_CARD_TYPE_FELICA:
            // FeliCa card reading
            {
                // FeliCa Read command
                BYTE cmdRead[12 + 6] = {
                    0x06, // Length of IDm (always 8)
                    0x00, // Command code for Read Without Encryption
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // IDm will be filled
                    0x01, // Number of services (1)
                    0x0B, 0x00, // Service code 000B = read
                    0x01, // Number of blocks (1)
                    0x80, // Block list element with 2-byte block list
                    blockNumber // Block number
                };
                
                // Copy IDm
                RtlCopyMemory(&cmdRead[2], pCardTypeInfo->FeliCa.IDm, 8);
                
                BYTE response[64];
                BYTE responseLen = sizeof(response);
                
                if(kull_m_pn532_DataExchange(comm, cmdRead, sizeof(cmdRead), response, &responseLen))
                {
                    if(responseLen >= blockLength + 12) // Response code + IDm + status + data
                    {
                        RtlCopyMemory(pBlockData, response + 12, blockLength);
                        status = TRUE;
                    }
                }
            }
            break;
            
        default:
            // Unsupported card type
            break;
    }
    
    return status;
}

LPCWSTR kull_m_pn532_GetCardDescription(PPN532_CARD_TYPE_INFO pCardTypeInfo)
{
    if(!pCardTypeInfo)
        return L"Unknown card";
    
    switch(pCardTypeInfo->Type)
    {
        case PN532_CARD_TYPE_A:
            {
                // MIFARE Classic detection logic
                if(pCardTypeInfo->TypeA.ATQA.ATQA[0] == 0x04 && 
                   pCardTypeInfo->TypeA.ATQA.ATQA[1] == 0x00 &&
                   pCardTypeInfo->TypeA.SAK == 0x08)
                    return L"MIFARE Classic 1K";
                    
                if(pCardTypeInfo->TypeA.ATQA.ATQA[0] == 0x02 && 
                   pCardTypeInfo->TypeA.ATQA.ATQA[1] == 0x00 &&
                   pCardTypeInfo->TypeA.SAK == 0x18)
                    return L"MIFARE Classic 4K";
                
                // MIFARE Ultralight detection logic
                if(pCardTypeInfo->TypeA.ATQA.ATQA[0] == 0x44 &&
                   pCardTypeInfo->TypeA.ATQA.ATQA[1] == 0x00 &&
                   pCardTypeInfo->TypeA.SAK == 0x00)
                    return L"MIFARE Ultralight";
                
                // DESFire detection
                if((pCardTypeInfo->TypeA.SAK & 0x20) == 0x20)
                    return L"MIFARE DESFire";
                    
                return L"ISO 14443A card";
            }
            
        case PN532_CARD_TYPE_B:
            return L"ISO 14443B card";
            
        case PN532_CARD_TYPE_FELICA:
            return L"FeliCa card";
            
        default:
            return L"Unknown card type";
    }
}

BOOL kull_m_pn532_InRelease(PKULL_M_PN532_COMM comm, const BYTE Tg)
{
	BOOL status = FALSE;
	BYTE ret;
	UINT16 wOut = sizeof(ret);
	if(kull_m_pn532_sendrecv(comm, PN532_CMD_InRelease, &Tg, sizeof(Tg), &ret, &wOut))
		status = !ret;
	return status;
}

BOOL kull_m_pn532_Mifare_Classic_AuthBlock(PKULL_M_PN532_COMM comm, PPN532_TARGET_TYPE_A target, const BYTE authKey, const BYTE blockId, const BYTE key[MIFARE_CLASSIC_KEY_SIZE])
{
	BOOL status = FALSE;
	PN532_DATA_EXCHANGE_MIFARE authBlock = {target->Tg, {authKey, blockId}};
	BYTE dataOut;
	UINT16 wOut = sizeof(dataOut);
	RtlCopyMemory(authBlock.DataOut.Data, key, MIFARE_CLASSIC_KEY_SIZE);
	RtlCopyMemory(authBlock.DataOut.Data + MIFARE_CLASSIC_KEY_SIZE, target->NFCID1, MIFARE_CLASSIC_UID_SIZE/*target->Target.TypeA.NFCIDLength*/); // !
	if(kull_m_pn532_sendrecv(comm, PN532_CMD_InDataExchange, (PBYTE) &authBlock, 13, &dataOut, &wOut))
		status = !dataOut;
	return status;
}

BOOL kull_m_pn532_Mifare_Classic_ReadBlock(PKULL_M_PN532_COMM comm, PPN532_TARGET_TYPE_A target, const BYTE blockId, PMIFARE_CLASSIC_RAW_BLOCK block)
{
	BOOL status = FALSE;
	PN532_DATA_EXCHANGE_MIFARE readBlock = {target->Tg, {MIFARE_CLASSIC_CMD_READ, blockId}};
	BYTE dataOut[MIFARE_CLASSIC_BLOCK_SIZE + 1];
	UINT16 wOut = sizeof(dataOut);
	RtlZeroMemory(block, sizeof(MIFARE_CLASSIC_RAW_BLOCK));
	if(kull_m_pn532_sendrecv(comm, PN532_CMD_InDataExchange, (PBYTE) &readBlock, 3, dataOut, &wOut))
		if(status = !dataOut[0])
			RtlCopyMemory(block->data, dataOut + 1, wOut - 1);
	return status;
}

BOOL kull_m_pn532_Mifare_Classic_ReadSector(PKULL_M_PN532_COMM comm, PPN532_TARGET_TYPE_A target, const BYTE sectorId, PMIFARE_CLASSIC_RAW_SECTOR sector)
{
	BOOL status = TRUE;
	BYTE i;
	RtlZeroMemory(sector, sizeof(MIFARE_CLASSIC_RAW_SECTOR));
	for(i = 0; i < MIFARE_CLASSIC_BLOCKS_PER_SECTOR; i++)
		status &= kull_m_pn532_Mifare_Classic_ReadBlock(comm, target, sectorId * MIFARE_CLASSIC_BLOCKS_PER_SECTOR + i, &sector->blocks[i]);
	return status;
}

BOOL kull_m_pn532_Mifare_Classic_ReadSectorWithKey(PKULL_M_PN532_COMM comm, PPN532_TARGET_TYPE_A target, const BYTE sectorId, const BYTE authKey, const BYTE key[MIFARE_CLASSIC_KEY_SIZE], PMIFARE_CLASSIC_RAW_SECTOR sector)
{
	BOOL status = FALSE;
	if(kull_m_pn532_Mifare_Classic_AuthBlock(comm, target, authKey, sectorId * MIFARE_CLASSIC_BLOCKS_PER_SECTOR, key))
		status = kull_m_pn532_Mifare_Classic_ReadSector(comm, target, sectorId, sector);
	return status;
}

const LPCWCHAR TgInitMode[] = {L"Mifare", L"Active mode", L"FeliCa"};
const UINT16 TgInitBaudrate[] = {106, 212, 424};
void kull_m_pn532_TgInitAsTarget(PKULL_M_PN532_COMM comm)
{
	BYTE dataIn[] = {	0x00,
						0x04, 0x00,		0x11, 0x22, 0x33,	0x08,
						
						0x01, 0xfe, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
						0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
						0xff, 0xff,

						0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
						0x00,
						0x00,
	};
	BYTE dataOut[PN532_MAX_LEN - 2];
	UINT16 wOut = sizeof(dataOut);

	if(kull_m_pn532_sendrecv(comm, PN532_CMD_TgInitAsTarget, dataIn, sizeof(dataIn), dataOut, &wOut))
	{
		kull_m_pn532_TgResponseToInitiator(comm);
		if(wOut)
		{
			kprintf(L"Framing Type        : %s\n", ((dataOut[0] & 3) < 3) ? TgInitMode[(dataOut[0] & 3)] : L"?");
			kprintf(L"DEP                 : %s\n", (dataOut[0] & 0x04) ? L"yes": L"no");
			kprintf(L"ISO/IEC 14443-4 PICC: %s\n", (dataOut[0] & 0x08) ? L"yes": L"no");
			kprintf(L"Baudrate            : %hu\n", (((dataOut[0] & 0x70) >> 4) < 3) ? TgInitBaudrate[((dataOut[0] & 0x70) >> 4)] : 0);
			if(wOut > 1)
			{
				kprintf(L"InitiatorCommand    : ");
				kull_m_string_wprintf_hex(dataOut + 1, wOut - 1, 1);
				kprintf(L"\n");
			}
		}
	}
}

void kull_m_pn532_TgGetInitiatorCommand(PKULL_M_PN532_COMM comm)
{
	BYTE dataOut[PN532_MAX_LEN - 2];
	UINT16 wOut = sizeof(dataOut);
	kprintf(L">> " TEXT(__FUNCTION__) L"\n");
	kull_m_pn532_sendrecv(comm, PN532_CMD_TgGetInitiatorCommand, NULL, 0, dataOut, &wOut);
}

void kull_m_pn532_TgResponseToInitiator(PKULL_M_PN532_COMM comm)
{
	BYTE dataIn[3] = {0x01, 0x20, 0x01};
	BYTE dataOut[PN532_MAX_LEN - 2];
	UINT16 wOut = sizeof(dataOut);

	kull_m_pn532_sendrecv(comm, PN532_CMD_TgResponseToInitiator, dataIn, sizeof(dataIn), dataOut, &wOut);
}

void kull_m_pn532_TgGetData(PKULL_M_PN532_COMM comm)
{
	BYTE dataOut[PN532_MAX_LEN - 2];
	UINT16 wOut = sizeof(dataOut);
	kprintf(L">> " TEXT(__FUNCTION__) L"\n");
	kull_m_pn532_sendrecv(comm, PN532_CMD_TgGetData, NULL, 0, dataOut, &wOut);
}