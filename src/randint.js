"use strict";

const randint = (min, max, callback = Math.random) => {
  return Math.floor(callback() * (max - min + 1) + min);
};

// https://stackoverflow.com/a/19303725
const seedint = (min, max, seedRef) => {
  let next = seedRef[0];

  if (!next) {
    next++;
  }

  seedRef[0] = seedRef[0] + 1;

  return Math.abs(
    randint(min, max, () => Math.sin(next) * 10000 - Math.floor(next))
  );
};

const shuffle = (array) => [...array].sort(() => (randint(0, 1) ? 1 : -1));

module.exports = {
  randint,
  seedint,
  shuffle,
};
