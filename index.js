'use strict';

var xml2js = require('xml2js');
var WXBizMsgCrypt = require('wechat-crypto');

var load = function (stream, callback) {
  var buffers = [];
  stream.on('data', function (trunk) {
    buffers.push(trunk);
  });
  stream.on('end', function () {
    callback(null, Buffer.concat(buffers));
  });
  stream.once('error', callback);
};

/*!
 * 将xml2js解析出来的对象转换成直接可访问的对象
 */
var formatMessage = function (result) {
  var message = {};
  if (typeof result === 'object') {
    for (var key in result) {
      if (result[key].length === 1) {
        var val = result[key][0];
        if (typeof val === 'object') {
          message[key] = formatMessage(val);
        } else {
          message[key] = (val || '').trim();
        }
      } else {
        message = result[key].map(formatMessage);
      }
    }
  }
  return message;
};

var respond = function (handler) {
  return function (req, res, next) {
    res.reply = function () {
      res.writeHead(200);
      res.end('success');
    };

    handler.callback(req.suiteMessage, req, res, next);
  };
};

/**
 * 微信自动回复平台的内部的Handler对象
 * @param {Object} config 企业号的开发者配置对象
 * @param {Function} handle handle对象
 *
 * config:
 * ```
 * {
 *   token: '',          // 公众平台上，开发者设置的Token
 *   encodingAESKey: '', // 公众平台上，开发者设置的EncodingAESKey
 *   suiteid: '',         // 企业号的CorpId
 * }
 * ```
 */
var Handler = function (config, handle) {
  this.config = config;
  this.callback = handle;
};

/**
 * 根据Handler对象生成响应方法，并最终生成中间件函数
 */
Handler.prototype.middlewarify = function () {
  var that = this;
  var config = this.config;
  that.cryptor = new WXBizMsgCrypt(config.token, config.encodingAESKey, config.suiteid);
  var _respond = respond(this);

  return function (req, res, next) {
    var method = req.method;
    var signature = req.query.msg_signature;
    var timestamp = req.query.timestamp;
    var nonce = req.query.nonce;
    var cryptor = req.cryptor || that.cryptor;

    load(req, function (err, buf) {
      if (err) {
        return next(err);
      }
      var xml = buf.toString('utf8');
      if (!xml) {
        var emptyErr = new Error('body is empty');
        emptyErr.name = 'Wechat';
        return next(emptyErr);
      }
      xml2js.parseString(xml, {trim: true}, function (err, result) {
        if (err) {
          err.name = 'BadMessage' + err.name;
          return next(err);
        }
        var xml = formatMessage(result.xml);
        var encryptMessage = xml.Encrypt;
        if (signature !== cryptor.getSignature(timestamp, nonce, encryptMessage)) {
          res.writeHead(401);
          res.end('Invalid signature');
          return;
        }
        var decrypted = cryptor.decrypt(encryptMessage);
        var messageWrapXml = decrypted.message;
        if (messageWrapXml === '') {
          res.writeHead(401);
          res.end('Invalid suiteid');
          return;
        }
        req.weixin_xml = messageWrapXml;
        xml2js.parseString(messageWrapXml, {trim: true}, function (err, result) {
          if (err) {
            err.name = 'BadMessage' + err.name;
            return next(err);
          }
          req.suiteMessage = formatMessage(result.xml);
          _respond(req, res, next);
        });
      });
    });
  };
};

/**
 * 根据口令
 *
 * Examples:
 * 使用wechat作为自动回复中间件的三种方式
 * ```
 * wechat(config, function (message, req, res, next) {});
 * ```
 * @param {Object} config 企业号的开发者配置对象
 * @param {Function} handle 生成的回调函数，参见示例
 */
var middleware = function (config, handle) {
  return new Handler(config, handle).middlewarify();
};

module.exports = middleware;
