(function() {var implementors = {};
implementors["tower_http_digest"] = [{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.59.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"enum\" href=\"tower_http_digest/enum.Digest.html\" title=\"enum tower_http_digest::Digest\">Digest</a>","synthetic":false,"types":["tower_http_digest::digest::Digest"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.59.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"tower_http_digest/struct.SignerLayer.html\" title=\"struct tower_http_digest::SignerLayer\">SignerLayer</a>","synthetic":false,"types":["tower_http_digest::sign::SignerLayer"]},{"text":"impl&lt;S:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.59.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.59.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"tower_http_digest/struct.Signer.html\" title=\"struct tower_http_digest::Signer\">Signer</a>&lt;S&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;S: <a class=\"trait\" href=\"https://docs.rs/tower-service/0.3.1/tower_service/trait.Service.html\" title=\"trait tower_service::Service\">Service</a>&lt;<a class=\"struct\" href=\"https://docs.rs/http/0.2.6/http/request/struct.Request.html\" title=\"struct http::request::Request\">Request</a>&lt;<a class=\"struct\" href=\"https://docs.rs/http-body/0.4.4/http_body/full/struct.Full.html\" title=\"struct http_body::full::Full\">Full</a>&lt;Bytes&gt;&gt;&gt;,&nbsp;</span>","synthetic":false,"types":["tower_http_digest::sign::Signer"]},{"text":"impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.59.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"tower_http_digest/struct.VerifierLayer.html\" title=\"struct tower_http_digest::VerifierLayer\">VerifierLayer</a>","synthetic":false,"types":["tower_http_digest::verify::VerifierLayer"]},{"text":"impl&lt;S:&nbsp;<a class=\"trait\" href=\"https://doc.rust-lang.org/1.59.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.59.0/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> for <a class=\"struct\" href=\"tower_http_digest/struct.Verifier.html\" title=\"struct tower_http_digest::Verifier\">Verifier</a>&lt;S&gt; <span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;S: <a class=\"trait\" href=\"https://docs.rs/tower-service/0.3.1/tower_service/trait.Service.html\" title=\"trait tower_service::Service\">Service</a>&lt;<a class=\"struct\" href=\"https://docs.rs/http/0.2.6/http/request/struct.Request.html\" title=\"struct http::request::Request\">Request</a>&lt;<a class=\"struct\" href=\"https://docs.rs/http-body/0.4.4/http_body/full/struct.Full.html\" title=\"struct http_body::full::Full\">Full</a>&lt;Bytes&gt;&gt;&gt;,&nbsp;</span>","synthetic":false,"types":["tower_http_digest::verify::Verifier"]}];
if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()