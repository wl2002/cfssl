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

  var table = {
    view: function(ctrl, args) {
      return m('table.table.table-bordered.table-striped', [
        m('thead', [
          m('tr', args.columns.map(function(column) {
            return m('th', column);
          }))
        ]),
        m('tbody', args.rows.map(function(row) {
          return m('tr', row.map(function(cell) {
            return m('td', cell);
          }));
        }))
      ]);
    }
  };

  var listGroup = {
    view: function(ctrl, children) {
      return m('ul.list-group', children.map(function(item) {
        return m('li.list-group-item', item);
      }));
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
      function broad() {
        var ICAs = results.IntermediateCAs();
        var out = [];

        out.push(m('h3.page-header', 'Broad'));

        if (ICAs && ICAs.grade) {
          out.push(m.component(panel, {
            grade: ICAs.grade,
            title: 'Intermediate Certificate Authorities'
          }));
        }

        if (out.length === 1) {
          return;
        }

        return out;
      }

      function connectivity() {
        var DNSLookup = results.DNSLookup();
        var TCPDial = results.TCPDial();
        var TLSDial = results.TLSDial();
        var out = [];

        out.push(m('h3.page-header', 'Connectivity'));

        if (DNSLookup && DNSLookup.grade) {
          out.push(m.component(panel, {
            grade: DNSLookup.grade,
            title: 'DNS Lookup'
          }, m.component(listGroup, DNSLookup.output.sort())));
        }

        if (TCPDial && TCPDial.grade) {
          out.push(m.component(panel, {
            grade: TCPDial.grade,
            title: 'TCP Dial'
          }));
        }

        if (TLSDial && TLSDial.grade) {
          out.push(m.component(panel, {
            grade: TLSDial.grade,
            title: 'TLS Dial'
          }));
        }

        if (out.length === 1) {
          return;
        }

        return out;
      }

      function tlssession() {
        var SessionResume = results.SessionResume();
        var out = [];

        out.push(m('h3.page-header', 'TLS Session'));

        if (SessionResume && SessionResume.grade) {
          var body;

          if (SessionResume.output) {
            body = m.component(table, {
              columns: ['Server', 'Supports TLS Resumption'],
              rows: Object.keys(SessionResume.output).sort().map(function(ip) {
                var supported = SessionResume.output[ip];

                return [
                  ip,
                  m('span.glyphicon.glyphicon-' + (supported ? 'ok-sign' : 'remove-sign'))
                ];
              })
            });
          }

          out.push(m.component(panel, {
            grade: SessionResume.grade,
            title: 'Session Resumption'
          }, body));
        }

        if (out.length === 1) {
          return;
        }

        return out;
      }

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
          broad(),
          connectivity(),
          tlssession(),
          m('h3.page-header', 'Public-Key Infrustructure (PKI)'),
          m.component(panel, {
            grade: scan.vm.Scan().ChainExpiration().grade,
            title: 'Chain Expiration',
            body: [
              m('p', 'The chain expiration date is the certificate, for your server, intermediatary, or root, that expires first.'),
              m('p', 'Certificates that use RSA should expire before X 2016, to be accepted by evergreen browsers.')
            ]
          }, m.component(listGroup, [
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
          ])),
          m.component(panel, {
            grade: scan.vm.Scan().ChainValidation().grade,
            title: 'Chain Validation',
            body: m('p', 'Blah blah, Chain Validation')
          }, scan.vm.Scan().ChainValidation().output && m.component(listGroup, [
            scan.vm.Scan().ChainValidation().output
          ])),
          m('h3.page-header', 'TLS Handshake'),
          m.component(panel, {
            grade: scan.vm.Scan().CipherSuite().grade,
            title: 'Cipher Suite Matrix',
            body: m('p', 'Explaination of this test.')
          }, scan.vm.Scan().CipherSuite().output && m.component(table, {
            columns: ['Cipher', 'TLS 1.2', 'TLS 1.1', 'TLS 1.0', 'SSL 3.0'],
            rows: scan.vm.Scan().CipherSuite().output.map(function(results) {
              var cipher = Object.keys(results)[0];
              var result = results[cipher];

              if (typeof result[0] === 'string') {
                return [
                  cipher,
                  result.indexOf('TLS 1.2') !== -1 ? m('span.glyphicon.glyphicon-ok-sign') : '-',
                  result.indexOf('TLS 1.1') !== -1 ? m('span.glyphicon.glyphicon-ok-sign') : '-',
                  result.indexOf('TLS 1.0') !== -1 ? m('span.glyphicon.glyphicon-ok-sign') : '-',
                  result.indexOf('SSL 3.0') !== -1 ? m('span.glyphicon.glyphicon-remove-sign') : '-'
                ];
              }

              return [
                cipher,
                result[0] && result[0]['TLS 1.2'][0] || '-',
                result[1] && result[1]['TLS 1.1'][0] || '-',
                result[2] && result[2]['TLS 1.0'][0] || '-',
                result[3] && result[3]['SSL 3.0'][0] || '-',
              ];
            })
          }))
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
          IntermediateCAs: response.Broad && response.Broad.IntermediateCAs,
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
}());
