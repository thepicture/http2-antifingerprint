"use strict";

const { randint } = require("./randint");

const shuffle = (array) => {
  return array.sort(() => (!!randint(0, 1) ? -1 : 1));
};

module.exports = {
  shuffle,
};
