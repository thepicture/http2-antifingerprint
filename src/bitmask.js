"use strict";

const bitmask = (array) => {
  return array.reduce((mask, current) => mask | current);
};

module.exports = {
  bitmask,
};
