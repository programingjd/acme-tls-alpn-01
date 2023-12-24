pub enum LetsEncrypt {
    ProductionEnvironment,
    StagingEnvironment,
}

#[cfg(debug_assertions)]
impl Default for LetsEncrypt {
    fn default() -> Self {
        Self::StagingEnvironment
    }
}

#[cfg(not(debug_assertions))]
impl Default for LetsEncrypt {
    fn default() -> Self {
        Self::ProductionEnvironment
    }
}

impl LetsEncrypt {
    pub fn domain(&self) -> &'static str {
        match self {
            LetsEncrypt::ProductionEnvironment => "acme-v02.api.letsencrypt.org",
            LetsEncrypt::StagingEnvironment => "acme-staging-v02.api.letsencrypt.org",
        }
    }
    pub fn directory_url(&self) -> String {
        format!("https://{}/directory", self.domain())
    }
}
