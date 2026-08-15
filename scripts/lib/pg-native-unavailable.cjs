"use strict";

const error = new Error(
  "The optional pg-native binding is unavailable in the reviewed live-drill runtime."
);
error.code = "MODULE_NOT_FOUND";
throw error;
