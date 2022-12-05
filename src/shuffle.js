const { randint } = require("./randint.js");

const shuffle = (array) => {
  return array.sort(() => (!!randint(0, 1) ? -1 : 1));
};

module.exports = {
  shuffle,
};
