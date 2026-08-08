
undefined4 sub_108c50(undefined4 param_1)

{
  undefined1 uVar1;
  undefined2 uVar2;
  undefined4 uVar3;
  int iVar4;
  undefined1 *puVar5;
  uint uVar6;
  void *pvVar7;
  undefined4 *puVar8;
  int in_ECX;
  float fVar9;
  undefined4 *unaff_FS_OFFSET;
  float10 fVar10;
  undefined4 uVar11;
  undefined4 uVar12;
  float fVar13;
  float fVar14;
  float fVar15;
  undefined4 uVar16;
  char *pcStack_110;
  undefined1 *puVar17;
  undefined1 local_f8 [4];
  undefined1 local_f4 [4];
  float local_f0;
  void *local_ec;
  undefined4 local_e8;
  undefined1 *local_e4 [2];
  int local_dc;
  undefined4 local_d8 [2];
  undefined1 local_d0 [8];
  float local_c8 [2];
  undefined4 local_c0;
  undefined4 local_bc;
  undefined4 local_b8;
  undefined4 local_b4;
  int local_b0;
  float local_ac;
  undefined1 local_a8 [16];
  undefined1 auStack_98 [8];
  float local_90 [2];
  undefined1 auStack_88 [8];
  undefined4 uStack_80;
  undefined4 uStack_7c;
  undefined4 uStack_78;
  undefined4 uStack_74;
  undefined1 local_70 [20];
  undefined1 local_5c [16];
  undefined1 local_4c [20];
  undefined1 local_38 [16];
  undefined1 local_28 [20];
  undefined4 local_14;
  undefined1 *puStack_10;
  int local_c;
  
  local_c = 0xffffffff;
  puStack_10 = &LAB_0071ba18;
  local_14 = *unaff_FS_OFFSET;
  *unaff_FS_OFFSET = &local_14;
  _pcStack_110 = (double)ZEXT48(local_f8);
  uVar3 = sub_11c90(param_1,&DAT_0073e9c0);
  _pcStack_110 = (double)ZEXT48(local_f8);
  **(undefined4 **)(in_ECX + 0x160) = uVar3;
  uVar3 = sub_11c90(param_1,"Creator_ID");
  _pcStack_110 = (double)ZEXT48(local_f8);
  *(undefined4 *)(*(int *)(in_ECX + 0x160) + 4) = uVar3;
  uVar3 = sub_11c20(param_1,"Version");
  *(undefined4 *)(*(int *)(in_ECX + 0x160) + 8) = uVar3;
  _pcStack_110 = 1.7658427352334887e-306;
  sub_1e5a90();
  _pcStack_110 = (double)CONCAT44(local_e4,local_f8);
  local_c = 0;
  uVar3 = sub_11ec0(local_d8,param_1,"Comments");
  local_c._0_1_ = 1;
  _pcStack_110 = (double)CONCAT44(uVar3,0x508d23);
  sub_1e5c50();
  local_c = (uint)local_c._1_3_ << 8;
  _pcStack_110 = (double)CONCAT44(0x508d33,pcStack_110);
  sub_1e5c20();
  local_c = 0xffffffff;
  _pcStack_110 = (double)CONCAT44(0x508d47,pcStack_110);
  sub_1e5c20();
  _pcStack_110 = (double)CONCAT44("Expansion_List",param_1);
  iVar4 = sub_118c0(local_70);
  if (iVar4 == 1) {
    _pcStack_110 = (double)CONCAT44(local_70,0x508d7c);
    local_ec = (void *)sub_11940();
    local_f0 = 0.0;
    if (0 < (int)local_ec) {
      do {
        _pcStack_110 = (double)CONCAT44(local_f0,local_70);
        sub_11990(local_f4);
        _pcStack_110 = 2.54665577412019e-313;
        puVar5 = operator_new(0xc);
        local_c = 2;
        local_e4[0] = puVar5;
        if (puVar5 == (undefined1 *)0x0) {
          puVar5 = (undefined1 *)0x0;
        }
        else {
          _pcStack_110 = (double)CONCAT44(0x508dd3,pcStack_110);
          sub_1e9e10();
        }
        local_c = 0xffffffff;
        if (puVar5 == (undefined1 *)0x0) {
          _pcStack_110 = (double)CONCAT44(0x509950,pcStack_110);
          sub_9b80();
          *unaff_FS_OFFSET = local_14;
          return 0;
        }
        _pcStack_110 = (double)CONCAT44(0x508df3,pcStack_110);
        uVar3 = sub_1e9e10();
        _pcStack_110 = (double)CONCAT44(uVar3,local_f8);
        local_c = 3;
        uVar3 = sub_11fd0(local_d8,local_f4,"Expansion_Name");
        local_c._0_1_ = 4;
        _pcStack_110 = (double)CONCAT44(uVar3,0x508e2e);
        sub_1e9e70();
        local_c = CONCAT31(local_c._1_3_,3);
        _pcStack_110 = (double)CONCAT44(0x508e3f,pcStack_110);
        sub_1ea000();
        local_c = 0xffffffff;
        _pcStack_110 = (double)CONCAT44(0x508e53,pcStack_110);
        sub_1ea000();
        _pcStack_110 = (double)ZEXT48(local_f8);
        uVar3 = sub_11c90(local_f4,"Expansion_ID");
        *(undefined4 *)(puVar5 + 8) = uVar3;
        _pcStack_110 = (double)CONCAT44(puVar5,0x508e7e);
        sub_1e9dc0();
        local_f0 = (float)((int)local_f0 + 1);
      } while ((int)local_f0 < (int)local_ec);
    }
  }
  _pcStack_110 = (double)CONCAT44(0x508e9c,pcStack_110);
  sub_1b3190();
  local_c = 5;
  _pcStack_110 = 1.7658427352336345e-306;
  sub_6d80();
  puVar17 = local_d0;
  pcStack_110 = (char *)&local_c0;
  sub_11e10(local_a8,param_1,"OnHeartbeat",local_f8);
  _pcStack_110 = (double)CONCAT44(puVar17,0x508ee1);
  sub_5f70();
  _pcStack_110 = (double)CONCAT44(local_d0,0x508ef1);
  sub_1e5c50();
  _pcStack_110 = 1.765842735233658e-306;
  sub_6d80();
  puVar17 = local_d0;
  pcStack_110 = (char *)&local_c0;
  sub_11e10(local_a8,param_1,"OnUserDefined",local_f8);
  _pcStack_110 = (double)CONCAT44(puVar17,0x508f2b);
  sub_5f70();
  _pcStack_110 = (double)CONCAT44(local_d0,0x508f3b);
  sub_1e5c50();
  _pcStack_110 = 1.7658427352336813e-306;
  sub_6d80();
  puVar17 = local_d0;
  pcStack_110 = (char *)&local_c0;
  sub_11e10(local_a8,param_1,"OnEnter",local_f8);
  _pcStack_110 = (double)CONCAT44(puVar17,0x508f75);
  sub_5f70();
  _pcStack_110 = (double)CONCAT44(local_d0,0x508f85);
  sub_1e5c50();
  _pcStack_110 = 1.7658427352337047e-306;
  sub_6d80();
  puVar17 = local_d0;
  pcStack_110 = (char *)&local_c0;
  sub_11e10(local_a8,param_1,"OnExit",local_f8);
  _pcStack_110 = (double)CONCAT44(puVar17,0x508fbf);
  sub_5f70();
  _pcStack_110 = (double)CONCAT44(local_d0,0x508fcf);
  sub_1e5c50();
  _pcStack_110 = (double)CONCAT44(0x508fd8,pcStack_110);
  uVar3 = sub_1e9e10();
  _pcStack_110 = (double)CONCAT44(uVar3,local_f8);
  local_c._0_1_ = 6;
  uVar3 = sub_11fd0(local_e4,param_1,&DAT_00745eec);
  local_c._0_1_ = 7;
  _pcStack_110 = (double)CONCAT44(uVar3,0x509011);
  sub_1e9e70();
  local_c._0_1_ = 6;
  _pcStack_110 = (double)CONCAT44(0x509021,pcStack_110);
  sub_1ea000();
  local_c._0_1_ = 5;
  _pcStack_110 = (double)CONCAT44(0x509032,pcStack_110);
  sub_1ea000();
  _pcStack_110 = 1.7658427352337594e-306;
  sub_1e5a90();
  _pcStack_110 = (double)CONCAT44(local_e4,local_f8);
  local_c._0_1_ = 8;
  sub_11ec0(local_c8,param_1,&DAT_00747a28);
  local_c._0_1_ = 9;
  _pcStack_110 = (double)CONCAT44(local_d8,0x50907d);
  uVar3 = sub_1e6080();
  local_c._0_1_ = 10;
  _pcStack_110 = (double)CONCAT44(uVar3,0x509091);
  sub_1e5c50();
  local_c._0_1_ = 9;
  _pcStack_110 = (double)CONCAT44(0x5090a1,pcStack_110);
  sub_1e5c20();
  local_c._0_1_ = 8;
  _pcStack_110 = (double)CONCAT44(0x5090b2,pcStack_110);
  sub_1e5c20();
  local_c = CONCAT31(local_c._1_3_,5);
  _pcStack_110 = (double)CONCAT44(0x5090c3,pcStack_110);
  sub_1e5c20();
  _pcStack_110 = (double)ZEXT48(local_f8);
  uVar3 = sub_11c20(param_1,"Flags");
  *(undefined4 *)(in_ECX + 4) = uVar3;
  _pcStack_110 = (double)ZEXT48(local_f8);
  uVar3 = sub_11c90(param_1,"CameraStyle");
  *(undefined4 *)(in_ECX + 0xb8) = uVar3;
  _pcStack_110 = 1.7658427352338232e-306;
  sub_6d80();
  _pcStack_110 = (double)CONCAT44(&local_c0,local_f8);
  uVar3 = sub_11e10(local_a8,param_1,"DefaultEnvMap");
  _pcStack_110 = (double)CONCAT44(uVar3,local_5c);
  sub_6120();
  *(undefined4 *)(in_ECX + 0x224) = 1;
  _pcStack_110 = (double)CONCAT44(0x509157,pcStack_110);
  iVar4 = sub_aee70();
  if (*(int *)(iVar4 + 0xe8) == 1) {
    puVar17 = (undefined1 *)0x0;
    pcStack_110 = (char *)0x50916e;
    sub_aee70();
    _pcStack_110 = (double)CONCAT44(puVar17,0x509175);
    sub_163a80();
  }
  _pcStack_110 = (double)CONCAT44(*(undefined4 *)(in_ECX + 0x2ac),local_f8);
  uVar6 = sub_11a60(param_1,"Unescapable");
  _pcStack_110 = (double)CONCAT44(*(undefined4 *)(in_ECX + 0x2b0),local_f8);
  *(uint *)(in_ECX + 0x2ac) = uVar6 & 0xff;
  uVar6 = sub_11a60(param_1,"RestrictMode");
  uVar6 = uVar6 & 0xff;
  if ((uVar6 != 0) && (*(uint *)(in_ECX + 0x2b0) != uVar6)) {
    puVar17 = (undefined1 *)0x1;
    pcStack_110 = (char *)0x5091d7;
    sub_aee70();
    _pcStack_110 = (double)CONCAT44(puVar17,0x5091de);
    sub_163c60();
  }
  _pcStack_110 = (double)ZEXT48(local_f8);
  *(uint *)(in_ECX + 0x2b0) = uVar6;
  uVar1 = sub_11c90(param_1,"ChanceRain");
  *(undefined1 *)(in_ECX + 0xa8) = uVar1;
  _pcStack_110 = (double)ZEXT48(local_f8);
  uVar1 = sub_11c90(param_1,"ChanceSnow");
  _pcStack_110 = (double)ZEXT48(local_f8);
  *(undefined1 *)(in_ECX + 0xa9) = uVar1;
  uVar3 = sub_11c90(param_1,"ChanceFog");
  _pcStack_110 = (double)ZEXT48(local_f8);
  *(undefined4 *)(in_ECX + 0x184) = uVar3;
  uVar1 = sub_11c90(param_1,"ChanceLightning");
  *(undefined1 *)(in_ECX + 0xaa) = uVar1;
  _pcStack_110 = (double)ZEXT48(local_f8);
  uVar1 = sub_11c90(param_1,"WindPower");
  *(undefined1 *)(in_ECX + 0xab) = uVar1;
  if ((*(byte *)(in_ECX + 4) & 1) != 0) {
    *(undefined1 *)(in_ECX + 0xa8) = 0;
    *(undefined1 *)(in_ECX + 0xa9) = 0;
    *(undefined1 *)(in_ECX + 0xaa) = 0;
    *(undefined1 *)(in_ECX + 0xab) = 0;
    *(undefined4 *)(in_ECX + 0x184) = 0;
  }
  _pcStack_110 = (double)ZEXT48(local_f8);
  uVar3 = sub_11c20(param_1,"MoonAmbientColor");
  _pcStack_110 = (double)ZEXT48(local_f8);
  *(undefined4 *)(in_ECX + 0x68) = uVar3;
  uVar3 = sub_11c20(param_1,"MoonDiffuseColor");
  *(undefined4 *)(in_ECX + 0x6c) = uVar3;
  _pcStack_110 = (double)ZEXT48(local_f8);
  uVar3 = sub_11c20(param_1,"MoonFogColor");
  _pcStack_110 = (double)CONCAT44(0x461c4000,local_f8);
  *(undefined4 *)(in_ECX + 0x70) = uVar3;
  fVar10 = (float10)sub_11d00(param_1,"MoonFogNear");
  *(float *)(in_ECX + 0x74) = (float)fVar10;
  if (fVar10 < (float10)0.0) {
    *(undefined4 *)(in_ECX + 0x74) = 0;
  }
  _pcStack_110 = (double)CONCAT44(0x461c4000,local_f8);
  fVar10 = (float10)sub_11d00(param_1,"MoonFogFar");
  *(float *)(in_ECX + 0x78) = (float)fVar10;
  if (fVar10 < (float10)0.0) {
    *(undefined4 *)(in_ECX + 0x78) = 0;
  }
  _pcStack_110 = (double)ZEXT48(local_f8);
  uVar1 = sub_11a60(param_1,"MoonFogOn");
  _pcStack_110 = (double)ZEXT48(local_f8);
  *(undefined1 *)(in_ECX + 0x7c) = uVar1;
  uVar6 = sub_11a60(param_1,"MoonShadows");
  _pcStack_110 = (double)ZEXT48(local_f8);
  *(uint *)(in_ECX + 0x80) = uVar6 & 0xff;
  uVar3 = sub_11c20(param_1,"SunAmbientColor");
  _pcStack_110 = (double)ZEXT48(local_f8);
  *(undefined4 *)(in_ECX + 0x84) = uVar3;
  uVar3 = sub_11c20(param_1,"SunDiffuseColor");
  _pcStack_110 = (double)ZEXT48(local_f8);
  *(undefined4 *)(in_ECX + 0x88) = uVar3;
  uVar3 = sub_11c20(param_1,"SunFogColor");
  *(undefined4 *)(in_ECX + 0x8c) = uVar3;
  _pcStack_110 = (double)CONCAT44(0x461c4000,local_f8);
  fVar10 = (float10)sub_11d00(param_1,"SunFogNear");
  *(float *)(in_ECX + 0x90) = (float)fVar10;
  if (fVar10 < (float10)0.0) {
    *(undefined4 *)(in_ECX + 0x90) = 0;
  }
  _pcStack_110 = (double)CONCAT44(0x461c4000,local_f8);
  fVar10 = (float10)sub_11d00(param_1,"SunFogFar");
  *(float *)(in_ECX + 0x94) = (float)fVar10;
  if (fVar10 < (float10)0.0) {
    *(undefined4 *)(in_ECX + 0x94) = 0;
  }
  _pcStack_110 = (double)ZEXT48(local_f8);
  uVar1 = sub_11a60(param_1,"SunFogOn");
  *(undefined1 *)(in_ECX + 0x98) = uVar1;
  _pcStack_110 = (double)ZEXT48(local_f8);
  uVar6 = sub_11a60(param_1,"SunShadows");
  _pcStack_110 = (double)ZEXT48(local_f8);
  *(uint *)(in_ECX + 0x9c) = uVar6 & 0xff;
  uVar6 = sub_11a60(param_1,"DayNightCycle");
  _pcStack_110 = (double)ZEXT48(local_f8);
  *(uint *)(in_ECX + 0xa0) = uVar6 & 0xff;
  uVar6 = sub_11a60(param_1,"IsNight");
  _pcStack_110 = (double)ZEXT48(local_f8);
  *(uint *)(in_ECX + 0xa4) = uVar6 & 0xff;
  uVar3 = sub_11c20(param_1,"DynAmbientColor");
  *(undefined4 *)(in_ECX + 0xac) = uVar3;
  _pcStack_110 = (double)CONCAT44(*(undefined4 *)(in_ECX + 0xb0),local_f8);
  uVar6 = sub_11a60(param_1,"NoRest");
  local_ec = (void *)CONCAT31(local_ec._1_3_,*(undefined1 *)(in_ECX + 0xb4));
  *(uint *)(in_ECX + 0xb0) = uVar6 & 0xff;
  _pcStack_110 = (double)CONCAT44(local_ec,local_f8);
  uVar1 = sub_11a60(param_1,"ShadowOpacity");
  *(undefined1 *)(in_ECX + 0xb4) = uVar1;
  _pcStack_110 = (double)ZEXT48(local_f8);
  uVar1 = sub_11a60(param_1,"LightingScheme");
  _pcStack_110 = (double)ZEXT48(local_f8);
  *(undefined1 *)(in_ECX + 0x222) = uVar1;
  uVar3 = sub_11c90(param_1,"ModSpotCheck");
  *(undefined4 *)(in_ECX + 0x188) = uVar3;
  _pcStack_110 = (double)ZEXT48(local_f8);
  uVar3 = sub_11c90(param_1,"ModListenCheck");
  *(undefined4 *)(in_ECX + 0x18c) = uVar3;
  _pcStack_110 = (double)CONCAT44("MiniGame",param_1);
  uVar3 = sub_11a10(local_f4);
  _pcStack_110 = (double)ZEXT48(local_f8);
  *(undefined4 *)(in_ECX + 0x234) = uVar3;
  uVar2 = sub_11b40(param_1,"LoadScreenID");
  _pcStack_110 = (double)ZEXT48(local_f8);
  *(undefined2 *)(in_ECX + 0x228) = uVar2;
  uVar3 = sub_11c20(param_1,"Grass_Diffuse");
  *(undefined4 *)(in_ECX + 0xd0) = uVar3;
  _pcStack_110 = (double)ZEXT48(local_f8);
  uVar3 = sub_11c20(param_1,"Grass_Ambient");
  _pcStack_110 = (double)ZEXT48(local_f8);
  *(undefined4 *)(in_ECX + 0xcc) = uVar3;
  fVar10 = (float10)sub_11d00(param_1,"Grass_Density");
  *(float *)(in_ECX + 0xd4) = (float)fVar10;
  _pcStack_110 = (double)ZEXT48(local_f8);
  fVar10 = (float10)sub_11d00(param_1,"Grass_QuadSize");
  *(float *)(in_ECX + 0xd8) = (float)fVar10;
  _pcStack_110 = 1.765842735234244e-306;
  sub_6d80();
  _pcStack_110 = (double)CONCAT44(&local_c0,local_f8);
  uVar3 = sub_11e10(local_a8,param_1,"Grass_TexName");
  _pcStack_110 = (double)CONCAT44(uVar3,local_5c);
  sub_6120();
  _pcStack_110 = (double)CONCAT44(0x50967a,pcStack_110);
  iVar4 = sub_6030();
  if (iVar4 == 0) {
    _pcStack_110 = (double)CONCAT44("grass",local_a8);
    sub_6290();
  }
  _pcStack_110 = (double)ZEXT48(local_f8);
  fVar10 = (float10)sub_11d00(param_1,"Grass_Prob_LL");
  *(float *)(in_ECX + 0xdc) = (float)fVar10;
  _pcStack_110 = (double)ZEXT48(local_f8);
  fVar10 = (float10)sub_11d00(param_1,"Grass_Prob_LR");
  *(float *)(in_ECX + 0xe0) = (float)fVar10;
  _pcStack_110 = (double)ZEXT48(local_f8);
  fVar10 = (float10)sub_11d00(param_1,"Grass_Prob_UL");
  *(float *)(in_ECX + 0xe4) = (float)fVar10;
  _pcStack_110 = (double)ZEXT48(local_f8);
  fVar10 = (float10)sub_11d00(param_1,"Grass_Prob_UR");
  *(float *)(in_ECX + 0xe8) = (float)fVar10;
  _pcStack_110 = (double)CONCAT44(0x3e4ccccd,local_f8);
  fVar10 = (float10)sub_11d00(param_1,"AlphaTest");
  *(float *)(in_ECX + 0xfc) = (float)fVar10;
  _pcStack_110 = (double)CONCAT44("Rooms",param_1);
  sub_118c0(local_70);
  _pcStack_110 = (double)CONCAT44(local_70,0x509754);
  uVar3 = sub_11940();
  *(undefined4 *)(in_ECX + 0x268) = uVar3;
  _pcStack_110 = (double)CONCAT44(uVar3,0x509762);
  sub_106910();
  local_f0 = 0.0;
  if (0 < *(int *)(in_ECX + 0x268)) {
    do {
      fVar9 = local_f0;
      _pcStack_110 = (double)CONCAT44(local_f0,local_70);
      sub_11990(local_f4);
      _pcStack_110 = 1.7658427352343554e-306;
      sub_1e5a90();
      _pcStack_110 = (double)CONCAT44(local_d8,local_f8);
      local_c._0_1_ = 0xb;
      uVar3 = sub_11ec0(local_5c,local_f4,"RoomName");
      local_c._0_1_ = 0xc;
      _pcStack_110 = (double)CONCAT44(uVar3,0x5097e9);
      sub_1e5c50();
      local_c._0_1_ = 0xb;
      _pcStack_110 = (double)CONCAT44(0x5097fd,pcStack_110);
      sub_1e5c20();
      local_c = CONCAT31(local_c._1_3_,5);
      _pcStack_110 = (double)CONCAT44(0x50980e,pcStack_110);
      sub_1e5c20();
      _pcStack_110 = (double)ZEXT48(local_f8);
      uVar3 = sub_11c90(local_f4,"EnvAudio");
      *(undefined4 *)(*(int *)(in_ECX + 0x260) + (int)fVar9 * 4) = uVar3;
      _pcStack_110 = (double)ZEXT48(local_f8);
      fVar10 = (float10)sub_11d00(local_f4,"AmbientScale");
      *(float *)(*(int *)(in_ECX + 0x264) + (int)fVar9 * 4) = (float)fVar10;
      _pcStack_110 = (double)CONCAT44("PartSounds",local_f4);
      iVar4 = sub_118c0(local_4c);
      if (iVar4 != 0) {
        _pcStack_110 = (double)CONCAT44(local_4c,0x509890);
        local_b0 = sub_11940();
        *(int *)(in_ECX + 0x26c) = *(int *)(in_ECX + 0x26c) + local_b0;
        local_dc = 0;
        if (0 < local_b0) {
          do {
            _pcStack_110 = (double)CONCAT44(local_dc,local_4c);
            sub_11990(&local_e8);
            local_e4[0] = (undefined1 *)&pcStack_110;
            sub_1e5b00(*(int *)(in_ECX + 0x25c) + (int)local_f0 * 8);
            sub_59a0();
            _pcStack_110 = (double)ZEXT48(local_f8);
            uVar6 = sub_11a60(&local_e8,"Looping");
            local_ac = (float)(uVar6 & 0xff);
            iVar4 = *(int *)(in_ECX + 0x284);
            if (*(int *)(in_ECX + 0x280) == iVar4) {
              if (iVar4 == 0) {
                iVar4 = 0x10;
              }
              else {
                iVar4 = iVar4 * 2;
              }
              local_ec = *(void **)(in_ECX + 0x27c);
              *(int *)(in_ECX + 0x284) = iVar4;
              _pcStack_110 = (double)CONCAT44(iVar4 * 4,0x50998b);
              pvVar7 = operator_new(iVar4 * 4);
              *(void **)(in_ECX + 0x27c) = pvVar7;
              iVar4 = 0;
              if (0 < *(int *)(in_ECX + 0x280)) {
                do {
                  *(undefined4 *)(*(int *)(in_ECX + 0x27c) + iVar4 * 4) =
                       *(undefined4 *)((int)local_ec + iVar4 * 4);
                  iVar4 = iVar4 + 1;
                } while (iVar4 < *(int *)(in_ECX + 0x280));
              }
              if (local_ec != (void *)0x0) {
                _pcStack_110 = (double)CONCAT44(local_ec,0x5099c9);
                _free(local_ec);
              }
            }
            *(float *)(*(int *)(in_ECX + 0x27c) + *(int *)(in_ECX + 0x280) * 4) = local_ac;
            *(int *)(in_ECX + 0x280) = *(int *)(in_ECX + 0x280) + 1;
            _pcStack_110 = 1.7658427352345467e-306;
            sub_1e5a90();
            local_e4[0] = (undefined1 *)&pcStack_110;
            local_c._0_1_ = 0xd;
            sub_11ec0(&pcStack_110,&local_e8,"ModelPart",local_f8,local_c8);
            sub_59a0();
            local_c._0_1_ = 5;
            _pcStack_110 = (double)CONCAT44(0x509a47,pcStack_110);
            sub_1e5c20();
            _pcStack_110 = 1.7658427352345755e-306;
            sub_1e5a90();
            local_e4[0] = (undefined1 *)&pcStack_110;
            local_c._0_1_ = 0xe;
            sub_11ec0(&pcStack_110,&local_e8,"OmenEvent",local_f8,local_90);
            sub_59a0();
            local_c = CONCAT31(local_c._1_3_,5);
            _pcStack_110 = (double)CONCAT44(0x509aa5,pcStack_110);
            sub_1e5c20();
            _pcStack_110 = 1.7658427352346052e-306;
            sub_6d80();
            _pcStack_110 = (double)CONCAT44(local_a8,local_f8);
            puVar8 = (undefined4 *)sub_11e10(local_38,&local_e8,"Sound");
            local_c0 = *puVar8;
            local_bc = puVar8[1];
            local_b8 = puVar8[2];
            local_b4 = puVar8[3];
            iVar4 = *(int *)(in_ECX + 0x2a8);
            if (*(int *)(in_ECX + 0x2a4) == iVar4) {
              if (iVar4 == 0) {
                iVar4 = 0x10;
              }
              else {
                iVar4 = iVar4 * 2;
              }
              _pcStack_110 = (double)CONCAT44(iVar4,0x509b14);
              sub_106e20();
            }
            *(int *)(in_ECX + 0x2a4) = *(int *)(in_ECX + 0x2a4) + 1;
            _pcStack_110 = (double)CONCAT44(&local_c0,local_28);
            sub_6120();
            local_dc = local_dc + 1;
            fVar9 = local_f0;
          } while (local_dc < local_b0);
        }
      }
      local_f0 = (float)((int)fVar9 + 1);
    } while ((int)local_f0 < *(int *)(in_ECX + 0x268));
  }
  _pcStack_110 = (double)CONCAT44(0x509b70,pcStack_110);
  iVar4 = sub_ae6b0();
  uStack_80 = *(undefined4 *)(iVar4 + 0x30);
  uStack_7c = *(undefined4 *)(iVar4 + 0x34);
  uStack_78 = *(undefined4 *)(iVar4 + 0x38);
  uStack_74 = *(undefined4 *)(iVar4 + 0x3c);
  _pcStack_110 = (double)CONCAT44(0x509ba6,pcStack_110);
  sub_1b3190();
  local_c._0_1_ = 0xf;
  _pcStack_110 = (double)CONCAT44(0x509bb7,pcStack_110);
  sub_1b3190();
  local_c = CONCAT31(local_c._1_3_,0x10);
  _pcStack_110 = (double)CONCAT44(auStack_88,0x509bd3);
  sub_5f70();
  _pcStack_110 = (double)CONCAT44(0x509bdf,pcStack_110);
  uVar3 = sub_1e5670();
  _pcStack_110 = (double)CONCAT44(uVar3,"lbl_map%s");
  sub_1e5680(auStack_98);
  _pcStack_110 = (double)CONCAT44(auStack_98,0x509c00);
  sub_6d60();
  _pcStack_110 = 1.48219693752374e-323;
  iVar4 = sub_8bc0(local_a8);
  if (iVar4 == 0) {
    _pcStack_110 = (double)CONCAT44(auStack_98,0x509c26);
    sub_6d60();
    _pcStack_110 = 1.48565539704463e-320;
    iVar4 = sub_8bc0(local_a8);
    if (iVar4 != 0) goto LAB_00509c4f;
  }
  else {
LAB_00509c4f:
    _pcStack_110 = (double)CONCAT44(&DAT_00747770,param_1);
    iVar4 = sub_11a10(local_f4);
    if (iVar4 != 0) {
      _pcStack_110 = (double)ZEXT48(local_f8);
      local_e4[0] = (undefined1 *)sub_11c90(local_f4,"MapResX");
      if (local_e4[0] != (undefined1 *)0x0) {
        _pcStack_110 = (double)ZEXT48(local_f8);
        local_d8[0] = sub_11c90(local_f4,"NorthAxis");
        _pcStack_110 = (double)CONCAT44(1,local_f8);
        local_b0 = sub_11c90(local_f4,"MapZoom");
        _pcStack_110 = -NAN;
        iVar4 = sub_11880(local_f4);
        if (iVar4 == 8) {
          _pcStack_110 = (double)ZEXT48(local_f8);
          fVar10 = (float10)sub_11d00(local_f4,"MapPt1X");
          _pcStack_110 = (double)(fVar10 * (float10)440.0 + (float10)0.5);
          sub_2fc750();
          _pcStack_110 = (double)CONCAT44(0x509d3a,pcStack_110);
          uVar3 = sub_2fae8c();
          _pcStack_110 = (double)ZEXT48(local_f8);
          fVar10 = (float10)sub_11d00(local_f4,"MapPt1Y");
          _pcStack_110 = (double)(fVar10 * (float10)256.0 + (float10)0.5);
          sub_2fc750();
          _pcStack_110 = (double)CONCAT44(0x509d77,pcStack_110);
          local_e8 = sub_2fae8c();
          _pcStack_110 = (double)ZEXT48(local_f8);
          fVar10 = (float10)sub_11d00(local_f4,"MapPt2X");
          _pcStack_110 = (double)(fVar10 * (float10)440.0 + (float10)0.5);
          sub_2fc750();
          _pcStack_110 = (double)CONCAT44(0x509db6,pcStack_110);
          local_dc = sub_2fae8c();
          _pcStack_110 = (double)ZEXT48(local_f8);
          fVar10 = (float10)sub_11d00(local_f4,"MapPt2Y");
          _pcStack_110 = (double)(fVar10 * (float10)256.0 + (float10)0.5);
          sub_2fc750();
          _pcStack_110 = (double)CONCAT44(0x509df5,pcStack_110);
          local_ec = (void *)sub_2fae8c();
        }
        else {
          _pcStack_110 = (double)ZEXT48(local_f8);
          uVar3 = sub_11c90(local_f4,"MapPt1X");
          _pcStack_110 = (double)ZEXT48(local_f8);
          local_e8 = sub_11c90(local_f4,"MapPt1Y");
          _pcStack_110 = (double)ZEXT48(local_f8);
          local_dc = sub_11c90(local_f4,"MapPt2X");
          _pcStack_110 = (double)ZEXT48(local_f8);
          local_ec = (void *)sub_11c90(local_f4,"MapPt2Y");
        }
        _pcStack_110 = (double)ZEXT48(local_f8);
        fVar10 = (float10)sub_11d00(local_f4,"WorldPt1X");
        local_c8[0] = (float)fVar10;
        _pcStack_110 = (double)ZEXT48(local_f8);
        fVar10 = (float10)sub_11d00(local_f4,"WorldPt1Y");
        local_90[0] = (float)fVar10;
        _pcStack_110 = (double)ZEXT48(local_f8);
        fVar10 = (float10)sub_11d00(local_f4,"WorldPt2X");
        local_f0 = (float)fVar10;
        _pcStack_110 = (double)ZEXT48(local_f8);
        fVar10 = (float10)sub_11d00(local_f4,"WorldPt2Y");
        local_ac = (float)fVar10;
        _pcStack_110 = (double)CONCAT44(0x509f01,pcStack_110);
        sub_ae6b0();
        _pcStack_110 = (double)CONCAT44(local_b0,local_ec);
        uVar11 = 1;
        puVar5 = local_e4[0];
        uVar12 = local_d8[0];
        fVar9 = local_c8[0];
        fVar13 = local_90[0];
        fVar14 = local_f0;
        fVar15 = local_ac;
        uVar16 = local_e8;
        iVar4 = local_dc;
        goto LAB_00509f60;
      }
    }
  }
  _pcStack_110 = (double)CONCAT44(0x509f48,pcStack_110);
  sub_ae6b0();
  _pcStack_110 = 2.12199579096527e-314;
  uVar3 = 0;
  uVar11 = 0;
  puVar5 = (undefined1 *)0x58;
  uVar12 = 0;
  fVar9 = 0.0;
  fVar13 = 0.0;
  fVar14 = 0.0;
  fVar15 = 0.0;
  uVar16 = 0;
  iVar4 = 0;
LAB_00509f60:
  sub_178c60(uVar11,puVar5,uVar12,fVar9,fVar13,fVar14,fVar15,uVar3,uVar16,iVar4);
  _pcStack_110 = (double)CONCAT44(*(undefined4 *)(in_ECX + 0x2b4),local_f8);
  uVar6 = sub_11c20(param_1,"StealthXPMax");
  if (uVar6 < *(uint *)(in_ECX + 0x2b8)) {
    *(uint *)(in_ECX + 0x2b8) = uVar6;
  }
  _pcStack_110 = (double)CONCAT44(uVar6,local_f8);
  *(uint *)(in_ECX + 0x2b4) = uVar6;
  uVar6 = sub_11c20(param_1,"StealthXPCurrent");
  if (*(uint *)(in_ECX + 0x2b4) < uVar6) {
    uVar6 = *(uint *)(in_ECX + 0x2b4);
  }
  *(uint *)(in_ECX + 0x2b8) = uVar6;
  _pcStack_110 = (double)CONCAT44(*(undefined4 *)(in_ECX + 700),local_f8);
  uVar3 = sub_11c20(param_1,"StealthXPLoss");
  *(undefined4 *)(in_ECX + 700) = uVar3;
  _pcStack_110 = (double)CONCAT44(*(undefined4 *)(in_ECX + 0x2c0),local_f8);
  uVar6 = sub_11a60(param_1,"StealthXPEnabled");
  *(uint *)(in_ECX + 0x2c0) = uVar6 & 0xff;
  _pcStack_110 = (double)(ulonglong)CONCAT14(*(undefined1 *)(in_ECX + 0x2c4),local_f8);
  uVar6 = sub_11a60(param_1,"TransPending");
  *(uint *)(in_ECX + 0x2c4) = uVar6 & 0xff;
  _pcStack_110 = (double)(ulonglong)CONCAT14(*(undefined1 *)(in_ECX + 0x2c8),local_f8);
  uVar1 = sub_11a60(param_1,"TransPendNextID");
  *(undefined1 *)(in_ECX + 0x2c8) = uVar1;
  _pcStack_110 = (double)(ulonglong)CONCAT14(*(undefined1 *)(in_ECX + 0x2c9),local_f8);
  uVar1 = sub_11a60(param_1,"TransPendCurrID");
  *(undefined1 *)(in_ECX + 0x2c9) = uVar1;
  local_c._0_1_ = 0xf;
  _pcStack_110 = (double)CONCAT44(0x50a093,pcStack_110);
  sub_1e5c20();
  local_c = CONCAT31(local_c._1_3_,5);
  _pcStack_110 = (double)CONCAT44(0x50a0a7,pcStack_110);
  sub_1e5c20();
  local_c = 0xffffffff;
  _pcStack_110 = (double)CONCAT44(0x50a0bb,pcStack_110);
  sub_1e5c20();
  *unaff_FS_OFFSET = local_14;
  return 1;
}
