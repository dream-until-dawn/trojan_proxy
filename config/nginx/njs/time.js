function getTimestamp(r) {
  r.return(200, Date.now().toString());
}

export default { getTimestamp };