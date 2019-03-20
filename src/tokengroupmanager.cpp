// Copyright (c) 2019 The ION Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "tokengroupmanager.h"

#include "rpc/protocol.h"
#include "utilstrencodings.h"

#include <univalue.h>
#include <iostream>
#include <regex>
#include <string.h>

std::shared_ptr<CTokenGroupManager> tokenGroupManager;

bool CTokenGroupManager::ValidateTokenDescription(const CTokenGroupInfo &tgInfo, const CTokenGroupDescription &tgDesc) {
    regex regexAlpha("^[a-zA-Z]+$");
    regex regexUrl(R"((https?|ftp)://(-\.)?([^\s/?\.#-]+\.?)+(/[^\s]*)?$)");

    smatch matchResult;

    if (!std::regex_match(tgDesc.strName, matchResult, regexAlpha)) {
        LogPrint("token", "Token name can only contain letters.\n");
        return false;
    }
    if (!std::regex_match(tgDesc.strTicker, matchResult, regexAlpha)) {
        LogPrint("token", "Token ticker can only contain letters.\n");
        return false;
    }
    if (!std::regex_match(tgDesc.strDocumentUrl, matchResult, regexUrl)) {
        LogPrint("token", "Token description document URL cannot be parsed.\n");
        return false;
    }
    if (tgDesc.decimalPos > 16) {
        LogPrint("token", "Token decimal separation position is too large, maximum is 16.\n");
        return false;
    }
    // Iterate existing token groups and verify that the new group has an unique ticker and name
    auto result = std::find_if(
          mapTokenGroups.begin(),
          mapTokenGroups.end(),
          [tgInfo, tgDesc](const std::pair<CTokenGroupID, CTokenGroupCreation>& tokenGroup) {
                if (tokenGroup.second.tokenGroupInfo.associatedGroup == tgInfo.associatedGroup) return false;
                bool exists = tokenGroup.second.tokenGroupDescription.strTicker == tgDesc.strTicker ||
                    tokenGroup.second.tokenGroupDescription.strName == tgDesc.strName;
                return exists;
            });
    if (result != mapTokenGroups.end()) {
        LogPrint("token", "Token ticker and name must be unique.\n");
        return false;
    };

    return true;
}

bool CTokenGroupManager::BuildGroupDescData(CScript script, std::vector<std::vector<unsigned char> > &descriptionData) {
    std::vector<std::vector<unsigned char> > desc;

    CScript::const_iterator pc = script.begin();
    std::vector<unsigned char> data;
    opcodetype opcode;

    if (!script.GetOp(pc, opcode, data)) return false;
    if (opcode != OP_RETURN) return false;

    if (!script.GetOp(pc, opcode, data)) return false;
    uint32_t OpRetGroupId;
    if (data.size()!=4) return false;
    OpRetGroupId = (uint32_t)data[3] << 24 | (uint32_t)data[2] << 16 | (uint32_t)data[1] << 8 | (uint32_t)data[0];
    if (OpRetGroupId != 88888888) return false;

    while (script.GetOp(pc, opcode, data)) {
        LogPrint("token", "Token description data: opcode=[%d] data=[%s]\n", opcode, std::string(data.begin(), data.end()));
        desc.emplace_back(data);
    }
    descriptionData = desc;
    return true;
}

bool CTokenGroupManager::ParseGroupDescData(const CTokenGroupInfo &tgInfo, const std::vector<std::vector<unsigned char> > descriptionData, CTokenGroupDescription &tokenGroupDescription) {
    std::string tickerStr;
    std::string name;
    std::string url;
    uint8_t decimalPos;
    uint256 docHash;
    
    try {
        tickerStr = std::string(descriptionData[0].begin(), descriptionData[0].end());
        name = std::string(descriptionData[1].begin(), descriptionData[1].end());
        decimalPos = (uint8_t)descriptionData[2][0];
        url = std::string(descriptionData[3].begin(), descriptionData[3].end());
        docHash = uint256(descriptionData[4]);
    } catch (const std::exception& e) {
        return false;
    }
    tokenGroupDescription = CTokenGroupDescription(tickerStr, name, decimalPos, url, docHash);
    if (!ValidateTokenDescription(tgInfo, tokenGroupDescription)) {
        tokenGroupDescription.Clear();
        tokenGroupDescription.invalid = true;
    }
    return !tokenGroupDescription.invalid;
}

bool CTokenGroupManager::ProcessManagementTokenGroups(CTokenGroupCreation tokenGroupCreation) {
    if (!tgMagicCreation && tokenGroupCreation.tokenGroupDescription.strTicker == "MAGIC") {
        this->tgMagicCreation = std::unique_ptr<CTokenGroupCreation>(new CTokenGroupCreation((tokenGroupCreation)));
        return true;
    } else if (!tgDarkMatterCreation && tokenGroupCreation.tokenGroupDescription.strTicker == "XDM") {
        this->tgDarkMatterCreation = std::unique_ptr<CTokenGroupCreation>(new CTokenGroupCreation((tokenGroupCreation)));
        return true;
    } else if (!tgAtomCreation && tokenGroupCreation.tokenGroupDescription.strTicker == "ATOM") {
        this->tgAtomCreation = std::unique_ptr<CTokenGroupCreation>(new CTokenGroupCreation((tokenGroupCreation)));
        return true;
    }
    return false;
}

void CTokenGroupManager::ClearManagementTokenGroups() {
    tgMagicCreation.reset();
    tgDarkMatterCreation.reset();
    tgAtomCreation.reset();
}

bool CTokenGroupManager::AddTokenGroups(const std::vector<CTokenGroupCreation>& newTokenGroups) {
    for (auto tokenGroupCreation : newTokenGroups) {
        ProcessManagementTokenGroups(tokenGroupCreation);

        std::pair<std::map<CTokenGroupID, CTokenGroupCreation>::iterator, bool> ret;
        ret = mapTokenGroups.insert(std::pair<CTokenGroupID, CTokenGroupCreation>(tokenGroupCreation.tokenGroupInfo.associatedGroup, tokenGroupCreation));

        CTokenGroupCreation& tokenGroupCreationRet = (*ret.first).second;
        bool fInsertedNew = ret.second;
        if (!fInsertedNew) {
            if (!(tokenGroupCreation == tokenGroupCreationRet)) {
                mapTokenGroups[tokenGroupCreation.tokenGroupInfo.associatedGroup] = tokenGroupCreation;
                // Token ID already exists. Since the hash is the same, the token specs are the same.
                // However, until reorgs are handled  properly: log this to avoid 'misplaced' token group creation transactions.
                LogPrint("token", "%s - Double token creation; updated.\n", __func__);
            } else {
                LogPrint("token", "%s - Double token creation; NOT updated.\n", __func__);
            }
        }
    }
    return true;
}
bool CTokenGroupManager::CreateTokenGroup(CTransaction tx, CTokenGroupCreation &newTokenGroupCreation) {
    CScript firstOpReturn;
    CTokenGroupInfo tokenGroupInfo;

    bool hasNewTokenGroup = false;

    for (const auto &txout : tx.vout) {
        const CScript &scriptPubKey = txout.scriptPubKey;
        CTokenGroupInfo tokenGrp(scriptPubKey);
        if ((txout.nValue == 0) && (firstOpReturn.size() == 0) && (txout.scriptPubKey[0] == OP_RETURN)) {
            firstOpReturn = txout.scriptPubKey;
        }
        if (tokenGrp.invalid)
            return false;
        if (tokenGrp.associatedGroup != NoGroup && tokenGrp.isGroupCreation() && !hasNewTokenGroup) {
            hasNewTokenGroup = true;
            tokenGroupInfo = tokenGrp;
        }
    }
    if (hasNewTokenGroup) {
        CTokenGroupDescription tokenGroupDescription;
        if (firstOpReturn.size()) {
            std::vector<std::vector<unsigned char> > desc;
            if (BuildGroupDescData(firstOpReturn, desc)) {
                ParseGroupDescData(tokenGroupInfo, desc, tokenGroupDescription);
            }
        }

        newTokenGroupCreation = CTokenGroupCreation(tx, tokenGroupInfo, tokenGroupDescription);
    }
    return true;
}

void CTokenGroupManager::ClearTokenGroups() {
    mapTokenGroups.clear();
}

bool CTokenGroupManager::RemoveTokenGroup(CTransaction tx, CTokenGroupID &newTokenGroupID) {
    CScript firstOpReturn;
    CTokenGroupInfo tokenGroupInfo;

    bool hasNewTokenGroup = false;

    for (const auto &txout : tx.vout) {
        const CScript &scriptPubKey = txout.scriptPubKey;
        CTokenGroupInfo tokenGrp(scriptPubKey);
        if ((txout.nValue == 0) && (firstOpReturn.size() == 0) && (txout.scriptPubKey[0] == OP_RETURN)) {
            firstOpReturn = txout.scriptPubKey;
        }
        if (tokenGrp.invalid)
            return false;
        if (tokenGrp.associatedGroup != NoGroup && tokenGrp.isGroupCreation() && !hasNewTokenGroup) {
            hasNewTokenGroup = true;
            tokenGroupInfo = tokenGrp;
        }
    }
    if (hasNewTokenGroup) {
        std::map<CTokenGroupID, CTokenGroupCreation>::iterator iter = mapTokenGroups.find(tokenGroupInfo.associatedGroup);
        if (iter != mapTokenGroups.end()) {
            mapTokenGroups.erase(iter);
            return true;
        }
    }
    return false;
}

CTokenGroupCreation CTokenGroupManager::GetTokenGroup(const CTokenGroupID& tgID) {
    return mapTokenGroups.at(tgID);
}
std::string CTokenGroupManager::GetTokenGroupNameByID(CTokenGroupID tokenGroupId) {
    CTokenGroupCreation tokenGroupCreation = mapTokenGroups.at(tokenGroupId);
    return "";
}

bool CTokenGroupManager::GetTokenGroupIdByTicker(std::string strTicker, CTokenGroupID &tokenGroupID) {
    auto result = std::find_if(
          mapTokenGroups.begin(),
          mapTokenGroups.end(),
          [strTicker](const std::pair<CTokenGroupID, CTokenGroupCreation>& tokenGroup) {
                return tokenGroup.second.tokenGroupDescription.strTicker == strTicker; 
            });
    if (result != mapTokenGroups.end()) {
        tokenGroupID = result->first;
        return true;
    };
    return false;
}

bool CTokenGroupManager::GetTokenGroupIdByName(std::string strName, CTokenGroupID &tokenGroupID) {
    auto result = std::find_if(
          mapTokenGroups.begin(),
          mapTokenGroups.end(),
          [strName](const std::pair<CTokenGroupID, CTokenGroupCreation>& tokenGroup) {
                return tokenGroup.second.tokenGroupDescription.strName == strName; 
            });
    if (result != mapTokenGroups.end()) {
        tokenGroupID = result->first;
        return true;
    };
    return false;
}

unsigned int CTokenGroupManager::GetXDMTxCount(const CBlock &block, const CCoinsViewCache& view, unsigned int &nXDMCount) {
    int nXDMCountInBlock = 0;
    for (auto tx : block.vtx) {
        if (!tx.IsCoinBase() && !tx.ContainsZerocoins()) {
            if (IsXDMTx(tx, view)) {
                nXDMCountInBlock++;
            }
        }
    }
    nXDMCount += nXDMCountInBlock;
    return nXDMCountInBlock;
}

bool CTokenGroupManager::IsXDMTx(const CTransaction &transaction, const CCoinsViewCache& view) {
    if (!tgDarkMatterCreation) return false;

    bool anyInputsXDM = false;
    if (!transaction.IsCoinBase() && !transaction.IsCoinStake() && !transaction.IsZerocoinSpend()) {

        if (!view.HaveInputs(transaction))
            return false;

        if (((int)chainActive.Tip()->nHeight >= Params().OpGroup_StartHeight())) {
            // Now iterate through the inputs to match to DarkMatter inputs
            for (const auto &inp : transaction.vin)
            {
                const COutPoint &prevout = inp.prevout;
                const Coin &coin = view.AccessCoin(prevout);
                if (coin.IsSpent()) {
                    LogPrint("token", "%s - Checking token group for spent coin\n", __func__);
                    return false;
                }
                // no prior coins can be grouped.
                if (coin.nHeight < Params().OpGroup_StartHeight())
                    continue;
                const CScript &script = coin.out.scriptPubKey;

                CTokenGroupInfo tokenGrp(script);
                // The prevout should never be invalid because that would mean that this node accepted a block with an
                // invalid OP_GROUP tx in it.
                if (tokenGrp.invalid)
                    continue;
                if (tokenGrp.associatedGroup == tgDarkMatterCreation->tokenGroupInfo.associatedGroup) {
                    LogPrint("token", "%s - Found a XDM input: [%s] at height [%d]\n", __func__, coin.out.ToString(), coin.nHeight);
                    anyInputsXDM = true;
                }
            }
        }
    }

    return anyInputsXDM;
}

bool CTokenGroupManager::TokenMoneyRange(CAmount nValueOut) {
    // Token amount max is 2^63-1 = 9223372036854775807
    return nValueOut >= 0 && nValueOut <= 922337203685477580;
}

CAmount CTokenGroupManager::AmountFromTokenValue(const UniValue& value, const CTokenGroupID& tgID) {
    if (!value.isNum() && !value.isStr())
        throw JSONRPCError(RPC_TYPE_ERROR, "Amount is not a number or string");
    CAmount amount;
    if (!ParseFixedPoint(value.getValStr(), GetTokenGroup(tgID).tokenGroupDescription.decimalPos, &amount))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");
    if (!TokenMoneyRange(amount))
        throw JSONRPCError(RPC_TYPE_ERROR, "Amount out of range");
    return amount;
}

UniValue CTokenGroupManager::TokenValueFromAmount(const CAmount& amount, const CTokenGroupID& tgID) {
    CAmount tokenCOIN = GetTokenGroup(tgID).tokenGroupDescription.GetCoin();
    bool sign = amount < 0;
    int64_t n_abs = (sign ? -amount : amount);
    int64_t quotient = n_abs / tokenCOIN;
    int64_t remainder = n_abs % tokenCOIN;
    return UniValue(UniValue::VNUM,
            strprintf("%s%d.%0*d", sign ? "-" : "", quotient, GetTokenGroup(tgID).tokenGroupDescription.decimalPos, remainder));
}

bool CTokenGroupManager::GetXDMFee(const uint32_t& nXDMTransactions, CAmount& fee) {
    if (!tgDarkMatterCreation) {
        fee = 0;
        return false;
    }
    CAmount XDMCoin = tgDarkMatterCreation->tokenGroupDescription.GetCoin();
    if (nXDMTransactions < 100000) {
        fee = 0.10 * XDMCoin;
    } else if (nXDMTransactions < 200000) {
        fee = 0.09 * XDMCoin;
    } else if (nXDMTransactions < 300000) {
        fee = 0.08 * XDMCoin;
    } else if (nXDMTransactions < 400000) {
        fee = 0.07 * XDMCoin;
    } else if (nXDMTransactions < 500000) {
        fee = 0.06 * XDMCoin;
    } else if (nXDMTransactions < 600000) {
        fee = 0.05 * XDMCoin;
    } else if (nXDMTransactions < 700000) {
        fee = 0.04 * XDMCoin;
    } else if (nXDMTransactions < 800000) {
        fee = 0.03 * XDMCoin;
    } else if (nXDMTransactions < 900000) {
        fee = 0.02 * XDMCoin;
    } else {
        fee = 0.01 * XDMCoin;
    }
    return true;
}

bool CTokenGroupManager::GetXDMFee(const CBlockIndex* pindex, CAmount& fee) {
    return GetXDMFee(pindex->nChainXDMTransactions, fee);
}

bool CTokenGroupManager::CheckXDMFees(const std::unordered_map<CTokenGroupID, CTokenGroupBalance>& tgMintMeltBalance, CValidationState& state, CBlockIndex* pindex, CAmount& nXDMFees) {
    // Creating a token costs a fee in XDM.
    // 10% of the weekly burned fees is distributed over masternode owners.
    // 10% of the weekly burned fees is distributed over atom token holders

    // A token group creation costs 5x the standard XDM fee
    // Max 1 token group creation per transaction

    CAmount XDMMelted = 0;
    CAmount feesNeeded = 0;
    CAmount curXDMFee;
    GetXDMFee(pindex, curXDMFee);
    for (auto bal : tgMintMeltBalance) {
        CTokenGroupCreation tg = GetTokenGroup(bal.first);
        if (bal.second.output - bal.second.input > 0) {
            if (!bal.first.hasFlag(TokenGroupIdFlags::MGT_TOKEN)) {
            }
        } else if (bal.second.output - bal.second.input < 0) {
            // Melt
            if (tg == *tgDarkMatterCreation) {
                XDMMelted += bal.second.output - bal.second.input;
            }
        }
    }
    // A token mint transaction costs 5x the standard XDM fee
/*
    for (auto tokenMint : newTokenMints) {

    }
*/
    // Check how many XDM has been melted
/*
    for (auto tokenMelt : newTokenMelts) {

    }
*/
    return true;
}