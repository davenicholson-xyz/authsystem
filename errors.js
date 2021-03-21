module.exports.authError = (error) => {
  if (error.code) {
    if (error.code === 11000) {
      let field = Object.keys(error.keyValue)[0];
      return `${field} has already been registered`;
    }
  }

  if (error.errors) {
    let validation = Object.values(error.errors)[0]?.properties?.message;
    return validation ?? `Something went wrong: ${error.toString()}`;
  }

  return error.message;
};
