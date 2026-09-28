import {assessmentFixture} from './staged-retention.mjs';
export function fixture() {
 const f=assessmentFixture(),c=JSON.parse(f.capsuleJson),m=JSON.parse(c.manifestJson);
 const j={schemaVersion:1,revision:9,operationId:m.operationId,manifestDigest:c.manifestDigest,generationDigest:c.generationDigest,catalogDigest:m.catalogDigest,inventoryDigest:m.inventoryDigest,controllerKeyId:c.controllerKeyId,requestedProfiles:['core'],status:'rolled-back',phase:'rollback',completedPhases:['discover','verify-manifest','verify-artifacts','snapshot'],changes:['work-created'],snapshot:{active:null,previous:null},restartRequired:false,failureCode:'RUNTIME_INTERNAL_ERROR',rollbackStatus:'succeeded'};
 return {failedState:f.failedState,controllerPublicKey:f.controllerPublicKey,targetBindingDigest:'D'.repeat(64),executorDigest:'E'.repeat(64),observation:{schemaVersion:1,capsuleJson:f.capsuleJson,journalJson:JSON.stringify(j),activeAbsent:true,previousAbsent:true,generationAbsent:true,tombstoneAbsent:true,archiveBytes:f.staged.archiveBytes,archiveSha256:f.staged.archiveSha256}};
}
