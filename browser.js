module.exports = function (parameters, prod) {
  const NEMID_ORIGIN = prod === true ? 'https://applet.danid.dk' : 'https://appletk.danid.dk'
  const element = document.createElement('iframe')
  element.id = 'nemid-' + Math.random().toString(32)
  element.classList.add('nemid-iframe')
  element.title = 'NemID'
  element.allowfullscreen = true
  element.src = `${NEMID_ORIGIN}/launcher/std/${element.id}`

  window.addEventListener('message', handler)

  var doneResolve
  var doneReject
  const done = new Promise((resolve, reject) => {
    doneResolve = resolve
    doneReject = reject
  })

  return {
    element,
    done
  }

  function handler (ev) {
    if (ev.origin !== NEMID_ORIGIN) return
    if (ev.source !== element.contentWindow) return

    // capture the event here
    ev.stopPropagation()

    var data = {}

    try {
      data = JSON.parse(ev.data)
    } catch (ex) {
      doneReject(new Error('Unexpected data: ' + ev.data))
      return false
    }

    const { command, content } = data

    if (command === 'SendParameters') {
      const res = { command: 'parameters', content: JSON.stringify(parameters) }
      element.contentWindow.postMessage(JSON.stringify(res), NEMID_ORIGIN)
      return false
    }

    if (command === 'changeResponseAndSubmit') {
      doneResolve(content)
      // Terminal condition
      window.removeEventListener('message', handler)
      return false
    }
  }
}
