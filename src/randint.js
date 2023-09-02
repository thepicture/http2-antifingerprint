"use strict";

const randint = (min, max) => {
  return Math.floor(Math.random() * (max - min + 1) + min);
};

const shuffle = (array) => [...array].sort(() => (randint(0, 1) ? 1 : -1));

module.exports = {
  randint,
  shuffle,
};
