// AUTO-GENERATED feature table, included by game.cpp.
// clang-format off

static const uint8_t patch_0[] = {0xe0, 0x7c, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6};
static const uint8_t patch_1[] = {0x00, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6};
static const uint8_t patch_2[] = {0xe0, 0xd3, 0x90, 0x52, 0x20, 0x00, 0xa0, 0x72, 0xc0, 0x03, 0x5f, 0xd6};
static const uint8_t patch_5[] = {0xe0, 0x3f, 0x99, 0x52, 0x40, 0x73, 0xa7, 0x72, 0xc0, 0x03, 0x5f, 0xd6};
static const uint8_t patch_7[] = {0xe0, 0x3f, 0x99, 0x52, 0x40, 0x73, 0xa7, 0x72, 0xc0, 0x03, 0x5f, 0xd6};
static const uint8_t patch_9[] = {0xe0, 0x3f, 0x99, 0x52, 0x40, 0x73, 0xa7, 0x72, 0xc0, 0x03, 0x5f, 0xd6};
static const uint8_t patch_12[] = {0xe0, 0x7c, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6};
static const uint8_t patch_14[] = {0xe0, 0x3f, 0x99, 0x52, 0x40, 0x73, 0xa7, 0x72, 0xc0, 0x03, 0x5f, 0xd6};
static const uint8_t patch_16[] = {0x20, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6};

static const modkit::FeatureDef g_features[game::kFeatureCount == 0 ? 1 : game::kFeatureCount] = {
  // id, key, label, group, kind, flags, slot, rva, off, width, def, lo, hi, patch
  {0, "infinite_ammo.Weapon.get_Ammo", "Infinite Ammo", "Combat", modkit::F_CONST_RETURN, modkit::F_NONE, -1, 0x1210, -1, 4, 999.0, 0.0, 1000000000.0, patch_0, 8},
  {1, "no_cooldown.Weapon.GetCooldown", "No Cooldown", "Combat", modkit::F_CONST_RETURN, modkit::F_NONE, -1, 0x1240, -1, 4, 0.0, 0.0, 1000000000.0, patch_1, 8},
  {2, "one_hit_kill.Weapon.GetDamage", "One Hit Kill", "Combat", modkit::F_CONST_RETURN, modkit::F_NONE, -1, 0x1230, -1, 4, 99999.0, 0.0, 1000000000.0, patch_2, 12},
  {3, "log_spawns.EnemySpawner.Spawn", "Log Enemy Spawns", "Debug", modkit::F_HOOK, modkit::F_NONE, -1, 0x1310, -1, 4, 1.0, 0.0, 1.0, nullptr, 0},
  {4, "economy.GameOptions.coins", "Coins → set", "Economy", modkit::F_VALUE_SET, modkit::F_NEEDS_INSTANCE, 0, 0x1410, -1, 4, 999999.0, 0.0, 1000000000.0, nullptr, 0},
  {5, "economy.GameOptions.coins.lock", "Coins lock", "Economy", modkit::F_CONST_RETURN, modkit::F_NONE, -1, 0x1400, -1, 4, 999999999.0, 0.0, 1000000000.0, patch_5, 12},
  {6, "economy.PlayerSave.gems", "Gems → set", "Economy", modkit::F_VALUE_SET, modkit::F_NEEDS_INSTANCE, 1, 0x1070, -1, 4, 999999.0, 0.0, 1000000000.0, nullptr, 0},
  {7, "economy.PlayerSave.gems.lock", "Gems lock", "Economy", modkit::F_CONST_RETURN, modkit::F_NONE, -1, 0x1060, -1, 4, 999999999.0, 0.0, 1000000000.0, patch_7, 12},
  {8, "economy.PlayerSave.gold", "Gold → set", "Economy", modkit::F_VALUE_SET, modkit::F_NEEDS_INSTANCE, 1, 0x1050, -1, 4, 999999.0, 0.0, 1000000000.0, nullptr, 0},
  {9, "economy.PlayerSave.gold.lock", "Gold lock", "Economy", modkit::F_CONST_RETURN, modkit::F_NONE, -1, 0x1040, -1, 4, 999999999.0, 0.0, 1000000000.0, patch_9, 12},
  {10, "movement.PlayerController.jumpsLeft.mem", "Jumpsleft → write", "Movement", modkit::F_FIELD_WRITE, modkit::F_NEEDS_INSTANCE, 2, 0, 0x2c, 4, 999999.0, 0.0, 1000000000.0, nullptr, 0},
  {11, "movement.PlayerController.moveSpeed", "Movespeed → set", "Movement", modkit::F_VALUE_SET, modkit::F_NEEDS_INSTANCE, 2, 0x1130, -1, 4, 10.0, -1000.0, 1000.0, nullptr, 0},
  {12, "movement.PlayerController.moveSpeed.lock", "Movespeed lock", "Movement", modkit::F_CONST_RETURN, modkit::F_NONE, -1, 0x1120, -1, 4, 999.0, -1000.0, 1000.0, patch_12, 8},
  {13, "progress.PlayerSave.level", "Level → set", "Progress", modkit::F_VALUE_SET, modkit::F_NEEDS_INSTANCE, 1, 0x1090, -1, 4, 999999.0, 0.0, 1000000000.0, nullptr, 0},
  {14, "progress.PlayerSave.level.lock", "Level lock", "Progress", modkit::F_CONST_RETURN, modkit::F_NONE, -1, 0x1080, -1, 4, 999999999.0, 0.0, 1000000000.0, patch_14, 12},
  {15, "unlock_all.PlayerSave.s_debugUnlocks", "Unlock Everything", "Progress", modkit::F_STATIC_WRITE, modkit::F_IS_STATIC, -1, 0x5010, 0x5010, 1, 1.0, 0.0, 1.0, nullptr, 0},
  {16, "god_mode.PlayerController.get_IsGodMode", "God Mode", "Survival", modkit::F_CONST_RETURN, modkit::F_NONE, -1, 0x1150, -1, 1, 1.0, 0.0, 1.0, patch_16, 8},
  {17, "god_mode.PlayerController.set_IsGodMode", "God Mode", "Survival", modkit::F_TOGGLE, modkit::F_NEEDS_INSTANCE, 2, 0x1140, -1, 1, 1.0, 0.0, 1.0, nullptr, 0},
  {18, "no_damage.PlayerController.TakeDamage", "Ignore Damage", "Survival", modkit::F_HOOK, modkit::F_DEFAULT_ON, -1, 0x1110, -1, 4, 1.0, 0.0, 1.0, nullptr, 0},
  {19, "survival.PlayerController.maxHealth.mem", "Maxhealth → write", "Survival", modkit::F_FIELD_WRITE, modkit::F_NEEDS_INSTANCE, 2, 0, 0x28, 4, 10.0, -1000.0, 1000.0, nullptr, 0},
  {20, "debug.save_now", "Save Now", "Utility", modkit::F_ACTION, modkit::F_NEEDS_INSTANCE, 1, 0x10a0, -1, 4, 1.0, 0.0, 1.0, nullptr, 0},
};

static modkit::HookDef g_capture_hooks[] = {
  {0x1420, 0, (void *)&rep_inst_GameOptions, (void **)&g_orig_inst_GameOptions, "capture NeonDrift.Save.GameOptions.UnlockAllTracks"},
  {0x10a0, 0, (void *)&rep_inst_PlayerSave, (void **)&g_orig_inst_PlayerSave, "capture NeonDrift.Save.PlayerSave.Save"},
  {0x1100, 0, (void *)&rep_inst_PlayerController, (void **)&g_orig_inst_PlayerController, "capture NeonDrift.Play.PlayerController.Update"},
};

static modkit::HookDef g_feature_hooks[] = {
  {0x1310, 0, (void *)&hk_3, (void **)&g_hk3_orig, "NeonDrift.Play.EnemySpawner::Spawn"},
  {0x1110, 0, (void *)&hk_18, (void **)&g_hk18_orig, "NeonDrift.Play.PlayerController::TakeDamage"},
};
// clang-format on
