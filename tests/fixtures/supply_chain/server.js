/** W5 fixture stub so discovery has a JS file to attach.

Lab analogue: Appsecco ``vulnerable-mcp-server-outdated-pacakges`` (pinned
vulnerable deps). MCPAegis W5 always flags npm *install scripts*; ``npm audit``
is optional and not required for this tree.

Handshake-safe: no child_process, no network. The finding lives in package.json
(``postinstall``), not in this handler.
*/
function echo(text) {
  return text;
}

module.exports = { echo };
