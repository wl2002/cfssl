(function() {
  'use strict';
  /* globals m */

  // > framework extensions
  m.deferred.resolve = function (value) {
    var deferred = m.deferred();
    deferred.resolve(value);
    return deferred.promise;
  };

  m.deferred.reject = function (value) {
    var deferred = m.deferred();
    deferred.reject(value);
    return deferred.promise;
  };
  // < framework extensions

  var page = (function() {
    var title = '';

    return {
      title: function(store) {
        if (arguments.length > 0) {
          title = store;

          if (!title.length) {
            document.title = 'CFSSL';
          } else {
            document.title = title + ' | CFSSL';
          }
        }

        return title;
      }
    };
  }());

  function appWrapper(module) {
    function navLink(selector, route, name) {
      var isActive = m.route().indexOf(route) === 0;
      selector += '[href="' + route + '"]';

      return m('li' + (isActive ? '.active' : ''), [
        m(selector, {
          config: m.route
        }, name)
      ]);
    }
    return [
      m('nav.navbar.navbar-default.navbar-static-top', [
        m('.container', [
          m('.navbar-header', [
            m('a.navbar-brand[href="/"]', {
              config: m.route
            }, 'CFSSL')
          ]),
          m('.collapse.navbar-collapse', [
            m('ul.nav.navbar-nav', [
              navLink('a', '/bundle', 'Bundle'),
              navLink('a', '/scan', 'Scan')
            ])
          ])
        ])
      ]),
      m('.container', module),
      m('footer.container', {
        style: {
          paddingTop: '40px',
          paddingBottom: '40px',
          marginTop: '100px',
          borderTop: '1px solid #e5e5e5',
          textAlign: 'center'
        }
      }, [
        m('p', [
          'Code licensed under ',
          m('a[href="https://github.com/cloudflare/cfssl/blob/master/LICENSE"]', 'BSD-2-Clause'),
          '.'
        ])
      ])
    ];
  }

  var panel = {
    view: function(ctrl, args, children) {
      function gradeToGlyphicon(grade) {
        switch(grade) {
          case 'Good':
            return 'glyphicon-ok-sign';
          case 'Warning':
            return 'glyphicon-exclamation-sign';
          case 'Bad':
            return 'glyphicon-remove-sign';
          default:
            return 'glyphicon-question-sign';
        }
      }

      function gradeToPanel(grade) {
        switch(grade) {
          case 'Good':
            return 'panel-success';
          case 'Warning':
            return 'panel-warning';
          case 'Bad':
            return 'panel-danger';
          default:
            return 'panel-default';
        }
      }

      return m('.panel.' + gradeToPanel(args.grade), [
        m('.panel-heading', [
          m('span.glyphicon.' + gradeToGlyphicon(args.grade)),
          ' ',
          args.title
        ]),
        m('.panel-body', args.body),
        children
      ]);
    }
  };

  var home = {
    controller: function() {
      page.title('');
      return;
    },
    view: function() {
      return appWrapper([
        m('h1.page-header', 'CFSSL: CloudFlare\'s PKI toolkit'), m('p', [
          'See ',
          m('a[href="https://blog.cloudflare.com/introducing-cfssl"]', 'blog post'),
          ' or ',
          m('a[href="https://github.com/cloudflare/cfssl"]', 'contribute on GitHub'),
          '.'
        ])
      ]);
    }
  };

  var scan = {
    vm: {
      init: function(domain) {
        scan.vm.domain = m.prop(domain ? domain : '');
        scan.vm.loading = m.prop(false);
        scan.vm.Scan = m.prop(false);
        scan.vm.scan = function(evt) {
          var domain = scan.vm.domain();
          scan.vm.Scan(false);
          scan.vm.loading(true);

          if (evt) {
            evt.preventDefault();
          }

          setTimeout(function() {
            scan.Model.scan(domain).then(function(result) {
              scan.vm.loading(false);
              scan.vm.Scan(result);
            });
          }, 0);
        };

        // TODO: remove!
        if (domain) {
          scan.vm.loading(true);
          setTimeout(function() {
            scan.Model.scan(domain).then(function(result) {
              scan.vm.loading(false);
              scan.vm.Scan(result);
            });
          }, 0);
        }
      }
    },
    Model: function(data) {
      this.domain = m.prop(data.domain);
      this.IntermediateCAs = m.prop(data.IntermediateCAs);
      this.DNSLookup = m.prop(data.DNSLookup);
      this.TCPDial = m.prop(data.TCPDial);
      this.TLSDial = m.prop(data.TLSDial);
      this.ChainExpiration = m.prop(data.ChainExpiration);
      this.ChainValidation = m.prop(data.ChainValidation);
      this.CipherSuite = m.prop(data.CipherSuite);
      this.SessionResume = m.prop(data.SessionResume);
    },
    controller: function() {
      scan.vm.init(m.route.param('domain'));
      page.title('Scan');
      return;
    },
    view: function() {
      var results = scan.vm.Scan();
      return appWrapper([
        m('h1.page-header', 'Scan'),
        m('form.form-horizontal', [
          m('.form-group', [
            m('label.col-sm-2.control-label[for=scanhost]', 'Host'),
            m('.col-sm-8', [
              m('input.form-control#scanhost[placeholder="cfssl.org"]', {
                value: scan.vm.domain(),
                onchange: m.withAttr('value', scan.vm.domain)
              })
            ])
          ]),
          m('.form-group', [
            m('.col-sm-offset-2 col-sm-10', [
              m('button.btn.btn-default[type="submit"]', {
                onclick: scan.vm.scan,
                disabled: scan.vm.loading()
              }, 'Scan')
            ])
          ])
        ]),
        !scan.vm.loading() ? '' : [
          m('p', 'Scanning ' + scan.vm.domain())
        ],
        !results ? '' : [
          m('h2.page-header', 'Results for ' + scan.vm.Scan().domain()),
          m('h3.page-header', 'Broad'),
          m.component(panel, {
            grade: scan.vm.Scan().IntermediateCAs().grade,
            title: 'Intermediate Certificate Authorities',
            body: m('p', 'There were no intermediate certificate authorities to verify.')
          }),
          m('h3.page-header', 'Connectivity'),
          m.component(panel, {
            grade: scan.vm.Scan().DNSLookup().grade,
            title: 'DNS Lookup',
            body: m('p', 'We were able to retrive DNS records for the domain.')
          }, [
            m('ul.list-group', scan.vm.Scan().DNSLookup().output.sort().map(function(item) {
                return m('li.list-group-item', item);
              })
            )
          ]),
          m.component(panel, {
            grade: scan.vm.Scan().TCPDial().grade,
            title: 'TCP Dial',
            body: m('p', 'Explaination of TCP Dial.')
          }),
          m.component(panel, {
            grade: scan.vm.Scan().TLSDial().grade,
            title: 'TLS Dial',
            body: m('p', 'Explaination of TLS Dial.')
          }),
          m('h3.page-header', 'TLS Session'),
          m.component(panel, {
            grade: scan.vm.Scan().SessionResume().grade,
            title: 'Session Resumption',
            body: m('p', 'Test to confirm if your server successfully resumes a TLS session.')
          }, scan.vm.Scan().SessionResume().output && [
            m('table.table.table-bordered.table-striped', [
              m('thead', [
                m('tr', [
                  m('th', 'Server'),
                  m('th', 'Supports TLS Resumption')
                ])
              ]),
              m('tbody', Object.keys(scan.vm.Scan().SessionResume().output).sort().map(function(ip) {
                var supported = scan.vm.Scan().SessionResume().output[ip];

                return m('tr', [
                  m('td', ip),
                  m('td', [
                    m('span.glyphicon.glyphicon-' + (supported ? 'ok-sign' : 'remove-sign'))
                  ])
                ]);
              }))
            ])
          ]),
          m('h3.page-header', 'Public-Key Infrustructure (PKI)'),
          m.component(panel, {
            grade: scan.vm.Scan().ChainExpiration().grade,
            title: 'Chain Expiration',
            body: [
              m('p', 'The chain expiration date is the certificate, for your server, intermediatary, or root, that expires first.'),
              m('p', 'Certificates that use RSA should expire before X 2016, to be accepted by evergreen browsers.')
            ]
          }, [
            m('ul.list-group', [
              m('li.list-group-item', [
                m('time[datetime="' + scan.vm.Scan().ChainExpiration().output + '"]', (new Date(scan.vm.Scan().ChainExpiration().output)).toLocaleString('bestfit', {
                  weekday: 'long',
                  year: 'numeric',
                  month: 'long',
                  day: 'numeric',
                  hour: 'numeric',
                  minute: 'numeric',
                  second: 'numeric',
                  timeZone: 'UTC',
                  timeZoneName: 'short'
                }))
              ])
            ])
          ]),
          m.component(panel, {
            grade: scan.vm.Scan().ChainValidation().grade,
            title: 'Chain Validation',
            body: m('p', 'Blah blah, Chain Validation')
          }, scan.vm.Scan().ChainValidation().output && [
            m('ul.list-group', [
              m('li.list-group-item', scan.vm.Scan().ChainValidation().output)
            ])
          ]),
          m('h3.page-header', 'TLS Handshake'),
          m.component(panel, {
            grade: scan.vm.Scan().CipherSuite().grade,
            title: 'Cipher Suite Matrix',
            body: m('p', 'Explaination of this test.')
          }, scan.vm.Scan().CipherSuite().output && [
            m('table.table.table-bordered.table-striped', [
              m('thead', [
                m('tr', [
                  m('th', 'Cipher'),
                  m('th', 'TLS 1.2'),
                  m('th', 'TLS 1.1'),
                  m('th', 'TLS 1.0'),
                  m('th', 'SSL 3.0')
                ])
              ]),
              m('tbody', scan.vm.Scan().CipherSuite().output.map(function(results) {
                var cipher = Object.keys(results)[0];
                var result = results[cipher];

                if (typeof result[0] === 'string') {
                  return m('tr', [
                    m('td', cipher),
                    m('td', result.indexOf('TLS 1.2') !== -1 ? m('span.glyphicon.glyphicon-ok-sign') : '-'),
                    m('td', result.indexOf('TLS 1.1') !== -1 ? m('span.glyphicon.glyphicon-ok-sign') : '-'),
                    m('td', result.indexOf('TLS 1.0') !== -1 ? m('span.glyphicon.glyphicon-ok-sign') : '-'),
                    m('td', result.indexOf('SSL 3.0') !== -1 ? m('span.glyphicon.glyphicon-remove-sign') : '-')
                  ]);
                }

                return m('tr', [
                  m('td', cipher),
                  m('td', result[0] && result[0]['TLS 1.2'][0] || '-'),
                  m('td', result[1] && result[1]['TLS 1.1'][0] || '-'),
                  m('td', result[2] && result[2]['TLS 1.0'][0] || '-'),
                  m('td', result[3] && result[3]['SSL 3.0'][0] || '-')
                ]);
              }))
            ])
          ])
        ]
      ]);
    }
  };

  scan.Model.scan = function(domain) {
    if (domain) {
      return m.request({
        method: 'GET',
        url: '/api/v1/cfssl/scan',
        data: {
          host: domain
        },
        unwrapSuccess: function(response) {
          if (!response.success) {
            throw new Error(response.messages.join(', '));
          }

          return response.result;
        },
        unwrapError: function(response) {
          return response.errors;
        }
      })
      .then(function(response) {
        var results = new scan.Model({
          domain: domain,
          IntermediateCAs: response.Broad.IntermediateCAs,
          DNSLookup: response.Connectivity.DNSLookup,
          TCPDial: response.Connectivity.TCPDial,
          TLSDial: response.Connectivity.TLSDial,
          ChainExpiration: response.PKI.ChainExpiration,
          ChainValidation: response.PKI.ChainValidation,
          CipherSuite: response.TLSHandshake.CipherSuite,
          SessionResume: response.TLSSession.SessionResume
        });

        return results;
      });
    }

    return m.deferred.reject();
  };

  m.route.mode = 'pathname';

  m.route(document.body, '/', {
    '/': home,
    '/scan': scan,
    '/scan/:domain': scan
  });

  window.scan = scan;
  window.bundle = bundle;
}());
