#  Copyright (C) 2024  Cypheriel
from typing import Literal, TypedDict


class LookupCustodian(TypedDict):
    codeLength: int
    maxSessionTTL: int


LookupAIDCConfigs = TypedDict(
    "LookupAIDCConfigs",
    {
        "threshold-getMyInfo": int,
        "threshold-certCertificate": int,
        "threshold-fetchCertificate": int,
        "threshold-findPerson": int,
    },
)


class LookupInheritance(TypedDict):
    durationBeforeNotSetupCFU: int
    staleInviteDuration: int


LookupConfigs = TypedDict(
    "LookupConfigs",
    {
        "is-in-line-flow-supported": bool,
        "2faUpgradeAccountTypePriority": list[str],
        "custodian": LookupCustodian,
        "appleOwnedDomains": list[str],
        "abs-enable": int,
        "firstPartyURLEntitlementCheckDisabled": bool,
        "aidc-cfgs": LookupAIDCConfigs,
        "inheritance": LookupInheritance,
        "baa-sign-sampling": int,
        "is-phone-number-supported": bool,
        "disablePSCreateAndForgetLink": bool,
        "appleIDAuthorizationUrls": list[str],
        "siwaw-allowed-domains": list[str],
    },
)


class LookupEnv(TypedDict):
    apsEnv: str
    idmsEnv: str


class LookupURLs(TypedDict):
    custodianIncompatibleDevices: str
    fetchBeneficiarySelectedDataOptions: str
    passwordAndSecurity: str
    webAccessDisable: str
    secondaryAuth: str
    fetchHmeList: str
    resetPasswordEmbargoDirect: str
    createCertificate: str
    acsURL: str
    dataRecoveryServiceDisable: str
    fetchGlobalConfigs: str
    custodianRecoveryValidate: str
    allowWebAccess: str
    followUpItems: str
    federatedAuthIntro: str
    personalInfo: str
    iCloudPlusFamShareHasFam: str
    createChildAccount: str
    ack_likeness: str
    managePrivateEmailAddress: str
    siwaManagementUrl: str
    custodianRecoveryStep: str
    fetch_likeness_self: str
    qualifyCert: str
    fetchPrimaryApp: str
    deleteAuthorizedApp: str
    pairingWSPrefix: str
    getMyInfo: str
    paymentAndShipping: str
    startCustodianSetup: str
    securityUpgrade: str
    trustedDeviceSecondaryAuth: str
    dataRecoveryServiceDisableComplete: str
    iForgotResetNotification: str
    repairDevices: str
    device_list_self: str
    webAccessKB: str
    userVerificationResult: str
    usePrivateEmailAddress: str
    InterceptRecoveryUrl: str
    verifyPhoneNumber: str
    webAccessEnable: str
    loadPersonalInfoUI: str
    updateBeneficiary: str
    midSyncMachine: str
    setupBeneficiary: str
    securityUpgradeEligibility: str
    postConfigData: str
    finishCustodianSetup: str
    updateDataRecoveryKey: str
    validateVettingToken: str
    completeBeneficiarySignIn: str
    loadFamilyPaymentCardUI: str
    iForgot: str
    qualifySession: str
    custodianRecoveryFeedback: str
    appleIDSignoutUrl: str
    familySharing: str
    simSwapUpdatePhoneNumber: str
    trustedDevices: str
    finishPasskeyRegistration: str
    resetPassword: str
    circle: str
    renewRecoveryToken: str
    walrusKB: str
    securityUpgradeVerification: str
    appleIDAuthorizeHTMLResponse: str
    generateVerificationToken: str
    midStartProvisioning: str
    accountReclaim: str
    manageRecoveryKey: str
    manageDataRecoveryService: str
    privacyRepair: str
    iCloudPlusFamShareHasSub: str
    delete_likeness: str
    gsService: str
    fetchAppleIdEmails: str
    loadPaymentUI: str
    storeModernRecoveryKey: str
    iCloudPlusFamShareNoFam: str
    trustedDevicesSummaryUrl: str
    addRegisteredTrustedPhoneNumber: str
    createPrivateEmailAddress: str
    removeBeneficiary: str
    securityUpgradeLearnMore: str
    dataRecoveryServiceEnable: str
    cancelBeneficiaryClaim: str
    fetchDataRecoveryKey: str
    secondaryAuthUrl: str
    verifyPrimaryEmail: str
    removeCustodian: str
    midFinishProvisioning: str
    registerHme: str
    securityUpgradeTearDown: str
    dataRecoveryServiceEnableComplete: str
    trustTransfer: str
    softwareUpdate: str
    resetPasswordEmbargo: str
    appleAccountRoot: str
    validateCode: str
    loadPaymentInfoUI: str
    setupPrivateRelay: str
    iCloudPlanUpgrade: str
    fetch_likeness: str
    fetchBeneficiaryDataSelectionOptions: str
    forcePasswordChange: str
    findPerson: str
    startPasskeyRegistration: str
    changePhoneNumber: str
    startCustodianRecovery: str
    createAccount: str
    fetchConfigData: str
    abortCustodianSetup: str
    tokenUpgrade: str
    deletePasskey: str
    iCloudStorageManage: str
    create_likeness: str
    postData: str
    appleIDAuthorize: str
    fetchAuthMode: str
    fetchAuthorizedApps: str
    fetchCertificate: str
    addPrimaryEmail: str
    changePasswordUrl: str
    expiredPassword: str
    update_likeness: str
    iForgotAppleIdLocked: str
    signInAlert: str
    fetchUserInfo: str
    addPhoneNumber: str
    managedAppleId: str
    teardown: str
    loadPasswordSecurityUI: str
    crossBorderPrivacyConsent: str
    repair: str
    updateNameUrl: str


class LookupResult(TypedDict):
    cfgs: LookupConfigs
    env: LookupEnv
    urls: LookupURLs


class ClientInfoResult(TypedDict):
    client_info: str
    user_agent: str


class Status(TypedDict):
    ed: str
    ec: int
    em: str


class StartProvisioningResult(TypedDict, total=False):
    Status: Status
    spim: str
    ptxid: str


EndProvisioningResult = TypedDict(
    "EndProvisioningResult",
    {
        "Status": Status,
        "X-Apple-I-MD-RINFO": str,
        "tk": str,
        "ptm": str,
        "ptxid": str,
    },
)

MachineHeadersFetchResult = TypedDict(
    "MachineHeadersFetchResult",
    {
        "Result": Literal["Headers"],
        "X-Apple-I-MD-M": str,
        "X-Apple-I-MD": str,
        "X-Apple-I-MD-RINFO": str,
    },
    total=False,
)
